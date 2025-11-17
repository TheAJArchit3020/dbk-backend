import Razorpay from "razorpay";
import crypto from "crypto";
import {
  AbstractPaymentProvider,
  MedusaError,
  BigNumber,
} from "@medusajs/framework/utils";

import type {
  // Inputs
  InitiatePaymentInput,
  AuthorizePaymentInput,
  CapturePaymentInput,
  CancelPaymentInput,
  DeletePaymentInput,
  GetPaymentStatusInput,
  RetrievePaymentInput,
  UpdatePaymentInput,
  ProviderWebhookPayload,
  // Outputs
  InitiatePaymentOutput,
  AuthorizePaymentOutput,
  CapturePaymentOutput,
  CancelPaymentOutput,
  DeletePaymentOutput,
  GetPaymentStatusOutput,
  RetrievePaymentOutput,
  UpdatePaymentOutput,
  WebhookActionResult,
  RefundPaymentInput,
  RefundPaymentOutput,
} from "@medusajs/framework/types";

import type { Logger } from "@medusajs/framework/types";
import { error } from "console";

/**
 * Provider options from medusa-config.ts
 */
type RazorpayOptions = {
  key_id: string;
  key_secret: string;
  webhook_secret?: string;
  auto_capture?: boolean;
};

type InjectedDeps = { logger: Logger };

/**
 * We store exactly what we need to complete later:
 * - order_id (Razorpay)
 * - amount_subunits (paise) and currency_code to avoid guessing later
 * - optional razorpay_payment_id/signature after checkout success
 */
type SessionData = {
  order_id: string;
  amount_subunits: number;
  currency_code: string;
  notes?: Record<string, unknown>;

  // Filled after checkout success handler (frontend) OR via webhook processing
  razorpay_payment_id?: string;
  razorpay_signature?: string;

  // When we fetch payment, keep a snapshot here
  payment?: Record<string, unknown>;
};

class RazorpayProviderService extends AbstractPaymentProvider<RazorpayOptions> {
  static identifier = "razorpay";

  protected logger_: Logger;
  protected options_: RazorpayOptions;
  protected client: Razorpay;

  constructor({ logger }: InjectedDeps, options: RazorpayOptions) {
    super({ logger }, options);
    this.logger_ = logger;
    this.options_ = options;

    if (!options.key_id || !options.key_secret) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Razorpay: key_id and key_secret are required."
      );
    }

    this.client = new Razorpay({
      key_id: options.key_id,
      key_secret: options.key_secret,
    });
  }

  /**
   * 1) INITIATE
   * - Medusa gives `amount` in RUPEES (as you observed).
   * - Razorpay expects SUBUNITS (paise) → multiply by 100.
   * - The PaymentProviderContext is limited (customer, account_holder, idempotency_key).
   *   We must not rely on custom fields. We’ll use idempotency_key as receipt.
   */
  async initiatePayment(
    input: InitiatePaymentInput
  ): Promise<InitiatePaymentOutput> {
    const { amount, currency_code, context } = input;

    if (typeof amount !== "number" || amount <= 0) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Razorpay: amount must be a positive number (in rupees)."
      );
    }

    // Convert rupees → paise safely
    const amount_subunits = Math.round(amount * 100);
    const currency = (currency_code || "INR").toUpperCase();

    const receipt = context?.idempotency_key || `medusa_${Date.now()}`;

    const order = await this.client.orders.create({
      amount: amount_subunits,
      currency,
      receipt,
      notes: {
        // keep minimal, nothing user-controlled/sensitive
        provider: context?.customer?.id || "",
      },
    });

    const data: SessionData = {
      order_id: order.id,
      amount_subunits,
      currency_code: currency,
      notes: order.notes as Record<string, unknown> | undefined,
    };

    return {
      id: order.id, // unique per payment session
      data,
    };
  }

  /**
   * 2) AUTHORIZE
   * Cart completion calls this.
   * If FE patched session with payment_id+signature via updatePayment, verify here.
   * Otherwise, return pending and rely on webhook.
   */
  async authorizePayment(
    input: AuthorizePaymentInput
  ): Promise<AuthorizePaymentOutput> {
    const data = (input.data || {}) as SessionData;
    console.log(data);
    const orderId = data.order_id;
    const paymentId = data.razorpay_payment_id;
    const signature = data.razorpay_signature;

    if (orderId && paymentId && signature) {
      // Verify checkout success signature
      const generated = crypto
        .createHmac("sha256", this.options_.key_secret)
        .update(`${orderId}|${paymentId}`)
        .digest("hex");

      if (generated !== signature) {
        throw new MedusaError(
          MedusaError.Types.INVALID_DATA,
          "Razorpay: signature verification failed."
        );
      }
      console.log("been here");
      // Fetch latest payment snapshot
      try {
        const payment = await this.client.payments.fetch(paymentId);
        console.log("been here too!!");
        const nextData: SessionData = {
          ...data,
          payment: payment as unknown as Record<string, unknown>,
        };
        console.log("Been here thrice!!");
        if (payment.status === "captured") {
          console.log("captures");
          return { data: nextData, status: "captured" };
        }
        if (payment.status === "authorized") {
          console.log("authorizes");
          return { data: nextData, status: "authorized" };
        }
        if (payment.status === "failed") {
          console.log("fails");
          return { data: nextData, status: "canceled" };
        }
        console.log("pends");
        return { data: nextData, status: "pending" };
      } catch (e) {
        console.log("error during payment fetch: ", e.message);
      }
    }

    // No sync checkout proof → let webhook flip it
    return { data, status: "pending" };
  }

  /**
   * 3) CAPTURE
   * Razorpay capture uses (paymentId, amount) optionally with { currency }.
   * Medusa v2 CapturePaymentInput does NOT give amount directly; use stored session data.
   */
  async capturePayment(
    input: CapturePaymentInput
  ): Promise<CapturePaymentOutput> {
    const data = (input.data || {}) as SessionData;
    const paymentId =
      (data.payment?.id as string | undefined) || data.razorpay_payment_id;

    if (!paymentId) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Razorpay: cannot capture – missing razorpay_payment_id (store it in session data first)."
      );
    }

    const amount = data.amount_subunits;
    const currency = data.currency_code || "INR";

    if (!amount || amount <= 0) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Razorpay: capture requires amount_subunits > 0 (saved in initiatePayment)."
      );
    }

    // Razorpay Node SDK: capture(paymentId, amount, { currency })
    const captured = await this.client.payments.capture(
      paymentId,
      amount.toString(),
      currency
    );

    return { data: { ...data, payment: captured } };
  }

  /**
   * 4) CANCEL (noop for Razorpay; there's no separate cancel)
   */
  async cancelPayment(input: CancelPaymentInput): Promise<CancelPaymentOutput> {
    return { data: input.data || {} };
  }

  /**
   * 5) DELETE payment session in provider (noop)
   */
  async deletePayment(input: DeletePaymentInput): Promise<DeletePaymentOutput> {
    return { data: input.data || {} };
  }

  /**
   * 6) RETRIEVE
   * Must return { data: ... } to satisfy PaymentProviderOutput.
   */
  async retrievePayment(
    input: RetrievePaymentInput
  ): Promise<RetrievePaymentOutput> {
    const data = (input.data || {}) as SessionData;
    const paymentId =
      (data.payment?.id as string | undefined) || data.razorpay_payment_id;
    const orderId = data.order_id;

    if (paymentId) {
      const payment = await this.client.payments.fetch(paymentId);
      return { data: { ...data, payment } };
    }
    if (orderId) {
      const order = await this.client.orders.fetch(orderId);
      return { data: { ...data, order } };
    }
    return { data };
  }

  /**
   * 7) STATUS
   * Safe polling against stored identifiers.
   */
  async getPaymentStatus(
    input: GetPaymentStatusInput
  ): Promise<GetPaymentStatusOutput> {
    const data = (input.data || {}) as SessionData;
    const paymentId =
      (data.payment?.id as string | undefined) || data.razorpay_payment_id;
    const orderId = data.order_id;

    try {
      if (paymentId) {
        const p = await this.client.payments.fetch(paymentId);
        switch (p.status) {
          case "authorized":
            return { status: "authorized" };
          case "captured":
            return { status: "captured" };
          case "failed":
            return { status: "canceled" };
          default:
            return { status: "pending" };
        }
      }
      if (orderId) {
        const o = await this.client.orders.fetch(orderId);
        // created | paid | attempted
        if (o.status === "paid") return { status: "captured" };
        return { status: "pending" };
      }
      return { status: "pending" };
    } catch {
      return { status: "pending" };
    }
  }

  /**
   * 8) WEBHOOK
   * Types are loose → we treat payload.data as unknown and coerce safely.
   * Always return { action, data: { session_id, amount } }.
   * session_id for Medusa is the internal payment session id; we don’t have it here.
   * In v2, returning session_id is optional; providing the same provider session id (order_id)
   * inside data lets Medusa correlate via the stored session (it has our order_id in data).
   */
  async getWebhookActionAndData(
    payload: ProviderWebhookPayload["payload"]
  ): Promise<WebhookActionResult> {
    const headers = (payload?.headers || {}) as Record<
      string,
      string | string[] | undefined
    >;
    const raw = (payload?.rawData ?? payload?.data) as unknown;

    // ---- verify webhook signature if configured ----
    if (this.options_.webhook_secret) {
      const sig =
        (headers["x-razorpay-signature"] as string) ||
        (headers["X-Razorpay-Signature"] as string) ||
        (Array.isArray(headers["x-razorpay-signature"])
          ? headers["x-razorpay-signature"][0]
          : undefined);

      const bodyStr =
        typeof raw === "string"
          ? raw
          : JSON.stringify(raw ?? payload?.data ?? {});

      const expected = crypto
        .createHmac("sha256", this.options_.webhook_secret)
        .update(bodyStr)
        .digest("hex");

      if (!sig || sig !== expected) {
        return {
          action: "failed",
          data: { session_id: "", amount: new BigNumber(0) },
        };
      }
    }

    // ---- coerce data shape defensively ----
    const obj: any =
      typeof payload?.data === "object" && payload?.data
        ? payload.data
        : typeof raw === "object" && raw
        ? raw
        : {};

    const event: string | undefined = obj.event || obj.event_type;
    const paymentEntity: any = obj?.payload?.payment?.entity;
    const orderEntity: any = obj?.payload?.order?.entity;

    // We didn’t store a true "session_id" (Medusa internal) with Razorpay,
    // so we feed back our order_id; Medusa correlates using session.data.order_id.
    const orderId: string | undefined =
      paymentEntity?.order_id || orderEntity?.id;

    const amountSubunits = Number(
      paymentEntity?.amount ?? orderEntity?.amount ?? 0
    );
    const amount = new BigNumber(amountSubunits);

    switch (event) {
      case "payment.authorized":
        return {
          action: "authorized",
          data: {
            // put the same id we saved in session.data so Medusa can match it
            session_id: orderId ?? "",
            amount,
          },
        };
      case "payment.captured":
      case "order.paid":
        return {
          action: "captured",
          data: {
            session_id: orderId ?? "",
            amount,
          },
        };
      case "payment.failed":
        return {
          action: "canceled",
          data: {
            session_id: orderId ?? "",
            amount,
          },
        };
      default:
        return {
          action: "not_supported",
          data: {
            session_id: orderId ?? "",
            amount,
          },
        };
    }
  }
  async refundPayment(input: RefundPaymentInput): Promise<RefundPaymentOutput> {
    throw new MedusaError(
      MedusaError.Types.NOT_ALLOWED,
      "Razorpay: refunds are not supported."
    );
  }
  /**
   * 9) UPDATE PAYMENT
   * FE can PATCH session with callback fields:
   *   { data: { order_id, razorpay_payment_id, razorpay_signature } }
   * We must return { data: ... } only (not context).
   */
  async updatePayment(input: UpdatePaymentInput): Promise<UpdatePaymentOutput> {
    // Merge into existing session data, return as 'data'
    const current = (input.data || {}) as SessionData;
    const merged: SessionData = { ...current };
    // Only copy the known fields to avoid surprises
    ["order_id", "razorpay_payment_id", "razorpay_signature"].forEach((k) => {
      const v = (input as any)?.context?.[k] ?? (input as any)?.data?.[k];
      if (typeof v === "string") {
        (merged as any)[k] = v;
      }
    });
    // if FE sent them under input.data (not context), keep them:
    const d = input.data as Record<string, unknown>;
    if (d) {
      if (typeof d["order_id"] === "string")
        merged.order_id = d["order_id"] as string;
      if (typeof d["razorpay_payment_id"] === "string")
        merged.razorpay_payment_id = d["razorpay_payment_id"] as string;
      if (typeof d["razorpay_signature"] === "string")
        merged.razorpay_signature = d["razorpay_signature"] as string;
    }

    return { data: merged };
  }

  static validateOptions(options: Record<any, any>) {
    if (!options.key_id || !options.key_secret) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Razorpay provider: key_id and key_secret are required."
      );
    }
  }
}

export default RazorpayProviderService;

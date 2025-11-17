// src/api/store/razorpay/confirm/route.ts
import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

type Body = {
  session_id: string; // payses_...
  order_id: string; // Razorpay order id (order_xxx)
  razorpay_payment_id: string;
  razorpay_signature: string;
  amount: string;
  currency_code: string;
};

export async function POST(req: MedusaRequest, res: MedusaResponse) {
  const {
    session_id,
    order_id,
    razorpay_payment_id,
    razorpay_signature,
    amount,
    currency_code,
  } = req.body as Body;

  if (!session_id || !order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: "Missing fields" });
  }

  // In v2 the DI token is usually "paymentModuleService"
  const paymentModule = req.scope.resolve("payment");

  const updated = await paymentModule.updatePaymentSession({
    id: session_id,
    amount,
    currency_code,
    data: {
      order_id,
      razorpay_payment_id,
      razorpay_signature,
    },
  });

  return res.json({ payment_session: updated });
}

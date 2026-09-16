import { orderDetails } from "./service";

// BOLA: the caller-chosen id crosses three modules; nothing checks ownership.
export function showOrder(orderId: number) {
  const order = orderDetails(orderId);
  return order;
}

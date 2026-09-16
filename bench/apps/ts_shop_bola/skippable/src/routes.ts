import { currentUserId } from "./auth";
import { orderDetails } from "./service";

// The check sits inside a skippable branch: it does not dominate the return.
export function showOrder(orderId: number, strict: boolean) {
  const order = orderDetails(orderId);
  if (strict) {
    if (order !== undefined && order.userId !== currentUserId()) {
      throw new Error("forbidden");
    }
  }
  return order;
}

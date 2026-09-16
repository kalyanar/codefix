import { currentUserId } from "./auth";
import { orderDetails } from "./service";

export function showOrder(orderId: number) {
  const order = orderDetails(orderId);
  if (order !== undefined && order.userId !== currentUserId()) {
    throw new Error("forbidden");
  }
  return order;
}

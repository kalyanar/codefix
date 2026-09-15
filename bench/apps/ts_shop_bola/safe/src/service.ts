import { loadOrder, Order } from "./repo";

export function orderDetails(oid: number): Order | undefined {
  const order = loadOrder(oid);
  return order;
}

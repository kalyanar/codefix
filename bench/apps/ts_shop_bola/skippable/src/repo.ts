export interface Order {
  id: number;
  userId: number;
  total: number;
}

const ORDERS = new Map<number, Order>([
  [1, { id: 1, userId: 1, total: 100 }],
  [2, { id: 2, userId: 2, total: 250 }],
]);

export function loadOrder(orderId: number): Order | undefined {
  return ORDERS.get(orderId);
}

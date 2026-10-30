type OrderState = { id: string; status: string };

// Retain the key while a request or payment is unresolved. A completed order
// must not prevent a later purchase of the same tariff in this open cabinet.
export class PurchaseRequests {
  private pending = new Map<string, { key: string; orderId?: string }>();

  keyFor(payload: string): string {
    let request = this.pending.get(payload);
    if (!request) {
      request = { key: crypto.randomUUID() };
      this.pending.set(payload, request);
    }
    return request.key;
  }

  received(payload: string, order: OrderState): void {
    const request = this.pending.get(payload);
    if (request) request.orderId = order.id;
    this.observe([order]);
  }

  observe(orders: OrderState[]): void {
    const finished = new Set(orders.filter(order => ["APPLIED", "CANCELED", "REFUNDED"].includes(order.status)).map(order => order.id));
    for (const [payload, request] of this.pending) {
      if (request.orderId && finished.has(request.orderId)) this.pending.delete(payload);
    }
  }

  clear(): void { this.pending.clear(); }
}

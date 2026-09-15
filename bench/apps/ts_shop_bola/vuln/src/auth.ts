let session: { uid: number | null } = { uid: null };

export function login(uid: number | null): void {
  session.uid = uid;
}

export function currentUserId(): number | null {
  return session.uid;
}

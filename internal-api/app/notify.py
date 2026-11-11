"""직원 알림 만들기 (화면 오른쪽 위 종 아이콘).

알림 문구에는 회원 코드·이름까지만 넣고 연락처·증빙 내용은 넣지 않는다.
알림 실패가 본 업무를 막지 않도록, 호출하는 쪽 트랜잭션 안에서 INSERT 만 한다.
"""


def to_users(conn, user_ids, kind: str, title: str, body: str | None = None, view: str | None = None,
             exclude=None) -> None:
    ids = {str(u) for u in user_ids if u} - ({str(exclude)} if exclude else set())
    for uid in ids:
        conn.execute("""INSERT INTO notifications (user_id, kind, title, body, link_view)
                        VALUES (%s, %s, %s, %s, %s)""", (uid, kind, title, body, view))


def to_role(conn, role: str, kind: str, title: str, body: str | None = None, view: str | None = None,
            exclude=None) -> None:
    rows = conn.execute("SELECT user_id FROM users WHERE role = %s AND active", (role,)).fetchall()
    to_users(conn, [r["user_id"] for r in rows], kind, title, body, view, exclude)


def to_counselors_of(conn, member_id, kind: str, title: str, body: str | None = None, view: str | None = None,
                     exclude=None) -> None:
    rows = conn.execute("SELECT user_id FROM assignments WHERE member_id = %s", (member_id,)).fetchall()
    to_users(conn, [r["user_id"] for r in rows], kind, title, body, view, exclude)


def member_label(conn, member_id) -> str:
    row = conn.execute("SELECT pseudo_id, name FROM members WHERE member_id = %s", (member_id,)).fetchone()
    return f"{row['pseudo_id']} {row['name']}" if row else "회원"

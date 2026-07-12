-- seed_watchlist.sql
-- Chạy TRƯỚC KHI replay violation.pcap để trigger rule_watchlist_match
-- Usage: psql -U pnads -d pnads -f scripts/seed_watchlist.sql

-- Xóa entry cũ nếu có (để idempotent khi chạy lại)
DELETE FROM watchlist WHERE mac = 'DE:AD:BE:EF:00:01';
DELETE FROM watchlist WHERE mac = 'BA:D0:CA:FE:00:02';

-- Entry 1: MAC của watchlist_violation device (sẽ khớp với violation.pcap)
INSERT INTO watchlist (mac, ip, label, note)
VALUES (
    'DE:AD:BE:EF:00:01',
    '192.168.1.250',
    'Thiết bị đáng ngờ - Demo',
    'MAC này xuất hiện trong sự kiện bảo mật 2025. Cảnh báo ngay khi thấy.'
);

-- Entry 2: Một trong những thiết bị mới trong violation.pcap  
INSERT INTO watchlist (mac, ip, label, note)
VALUES (
    'BA:D0:CA:FE:00:02',
    NULL,
    'Laptop lạ - rogue-laptop',
    'Phát hiện tại văn phòng, không rõ chủ sở hữu.'
);

-- Verify
SELECT id, mac, ip, label, created_at FROM watchlist ORDER BY id;

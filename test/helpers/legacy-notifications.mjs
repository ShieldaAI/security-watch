// Reconstruct the notification table consistently when creating a pre-schema-7 backup for a test.
export function removeAcceptanceSchema(db) {
  db.exec('DROP INDEX notifications_by_acceptance; ALTER TABLE notifications DROP COLUMN accepted_at;');
}

-- AlterTable
ALTER TABLE "instance_settings" ADD COLUMN     "password_login_enabled" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "recovery_mode_expires_at" TIMESTAMP(3),
ADD COLUMN     "recovery_mode_user_id" TEXT;

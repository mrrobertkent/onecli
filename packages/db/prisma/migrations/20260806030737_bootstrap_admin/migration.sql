-- AlterTable
ALTER TABLE "instance_settings" ADD COLUMN     "bootstrap_admin_user_id" TEXT;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "must_change_password" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE UNIQUE INDEX "instance_settings_bootstrap_admin_user_id_key" ON "instance_settings"("bootstrap_admin_user_id");

-- AddForeignKey
ALTER TABLE "instance_settings" ADD CONSTRAINT "instance_settings_bootstrap_admin_user_id_fkey" FOREIGN KEY ("bootstrap_admin_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;


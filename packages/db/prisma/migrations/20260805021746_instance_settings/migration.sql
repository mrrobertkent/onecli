-- CreateTable
CREATE TABLE "instance_settings" (
    "id" TEXT NOT NULL DEFAULT 'instance',
    "signup_mode" TEXT NOT NULL DEFAULT 'closed',
    "updated_at" TIMESTAMP(3) NOT NULL,
    "updated_by_user_id" TEXT,

    CONSTRAINT "instance_settings_pkey" PRIMARY KEY ("id")
);

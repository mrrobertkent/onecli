-- CreateTable
CREATE TABLE "recovery_tokens" (
    "id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "recovery_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "recovery_tokens_token_hash_key" ON "recovery_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "recovery_tokens_user_id_idx" ON "recovery_tokens"("user_id");

-- AddForeignKey
ALTER TABLE "recovery_tokens" ADD CONSTRAINT "recovery_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

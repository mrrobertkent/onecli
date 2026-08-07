-- AlterTable
ALTER TABLE "groups" ADD COLUMN     "membership_mode" TEXT NOT NULL DEFAULT 'explicit',
ADD COLUMN     "project_access_mode" TEXT NOT NULL DEFAULT 'selected';

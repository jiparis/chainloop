-- Create "workflow_run_cas_backends" table
CREATE TABLE "workflow_run_cas_backends" ("workflow_run_id" uuid NOT NULL, "cas_backend_id" uuid NOT NULL, PRIMARY KEY ("workflow_run_id", "cas_backend_id"), CONSTRAINT "workflow_run_cas_backends_cas_backend_id" FOREIGN KEY ("cas_backend_id") REFERENCES "cas_backends" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "workflow_run_cas_backends_workflow_run_id" FOREIGN KEY ("workflow_run_id") REFERENCES "workflow_runs" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
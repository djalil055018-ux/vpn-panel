--
-- PostgreSQL database dump
--


-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

--
-- Name: clients clients_client_id_key; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.clients
    ADD CONSTRAINT clients_client_id_key UNIQUE (client_id);


--
-- Name: clients clients_import_id_source_user_id_key; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.clients
    ADD CONSTRAINT clients_import_id_source_user_id_key UNIQUE (import_id, source_user_id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (import_id, client_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (import_id, node_id, client_id, sequence);


--
-- Name: nodes nodes_import_id_source_node_id_key; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.nodes
    ADD CONSTRAINT nodes_import_id_source_node_id_key UNIQUE (import_id, source_node_id);


--
-- Name: nodes nodes_node_id_key; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.nodes
    ADD CONSTRAINT nodes_node_id_key UNIQUE (node_id);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (import_id, node_id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (import_id);


--
-- Name: admin_accounts admin_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_accounts
    ADD CONSTRAINT admin_accounts_pkey PRIMARY KEY (id);


--
-- Name: admin_mfa admin_mfa_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_mfa
    ADD CONSTRAINT admin_mfa_pkey PRIMARY KEY (account_id);


--
-- Name: admin_sessions admin_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_pkey PRIMARY KEY (id);


--
-- Name: admin_sessions admin_sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: agent_fleet_attempts agent_fleet_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_attempts
    ADD CONSTRAINT agent_fleet_attempts_pkey PRIMARY KEY (job_id, claim_id);


--
-- Name: agent_fleet_jobs agent_fleet_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_jobs
    ADD CONSTRAINT agent_fleet_jobs_pkey PRIMARY KEY (id);


--
-- Name: agent_fleet_jobs agent_fleet_jobs_run_id_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_jobs
    ADD CONSTRAINT agent_fleet_jobs_run_id_node_id_key UNIQUE (run_id, node_id);


--
-- Name: agent_fleet_policy agent_fleet_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_policy
    ADD CONSTRAINT agent_fleet_policy_pkey PRIMARY KEY (singleton);


--
-- Name: agent_fleet_runs agent_fleet_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_runs
    ADD CONSTRAINT agent_fleet_runs_pkey PRIMARY KEY (id);


--
-- Name: agent_fleet_runs agent_fleet_runs_request_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_runs
    ADD CONSTRAINT agent_fleet_runs_request_key_key UNIQUE (request_key);


--
-- Name: agent_releases agent_releases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_releases
    ADD CONSTRAINT agent_releases_pkey PRIMARY KEY (version);


--
-- Name: agent_updaters agent_updaters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_updaters
    ADD CONSTRAINT agent_updaters_pkey PRIMARY KEY (node_id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: billing_entitlements billing_entitlements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_entitlements
    ADD CONSTRAINT billing_entitlements_pkey PRIMARY KEY (client_id, plan_id);


--
-- Name: billing_invoices billing_invoices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_pkey PRIMARY KEY (id);


--
-- Name: billing_invoices billing_invoices_tenant_id_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_tenant_id_idempotency_key_key UNIQUE (tenant_id, idempotency_key);


--
-- Name: billing_offers billing_offers_id_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_offers
    ADD CONSTRAINT billing_offers_id_tenant_id_key UNIQUE (id, tenant_id);


--
-- Name: billing_offers billing_offers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_offers
    ADD CONSTRAINT billing_offers_pkey PRIMARY KEY (id);


--
-- Name: billing_payment_events billing_payment_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_payment_events
    ADD CONSTRAINT billing_payment_events_pkey PRIMARY KEY (event_id);


--
-- Name: bot_account_squads bot_account_squads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_account_squads
    ADD CONSTRAINT bot_account_squads_pkey PRIMARY KEY (tenant_id, legacy_id, source_uuid);


--
-- Name: bot_accounts bot_accounts_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_accounts
    ADD CONSTRAINT bot_accounts_client_id_key UNIQUE (client_id);


--
-- Name: bot_accounts bot_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_accounts
    ADD CONSTRAINT bot_accounts_pkey PRIMARY KEY (tenant_id, legacy_id);


--
-- Name: bot_accounts bot_accounts_tenant_id_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_accounts
    ADD CONSTRAINT bot_accounts_tenant_id_username_key UNIQUE (tenant_id, username);


--
-- Name: bot_devices bot_devices_client_id_hwid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_devices
    ADD CONSTRAINT bot_devices_client_id_hwid_key UNIQUE (client_id, hwid);


--
-- Name: bot_devices bot_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_devices
    ADD CONSTRAINT bot_devices_pkey PRIMARY KEY (id);


--
-- Name: bot_devices bot_devices_tenant_id_legacy_id_hwid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_devices
    ADD CONSTRAINT bot_devices_tenant_id_legacy_id_hwid_key UNIQUE (tenant_id, legacy_id, hwid);


--
-- Name: bot_operations bot_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_operations
    ADD CONSTRAINT bot_operations_pkey PRIMARY KEY (tenant_id, operation_key);


--
-- Name: bot_profiles bot_profiles_import_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_profiles
    ADD CONSTRAINT bot_profiles_import_id_key UNIQUE (import_id);


--
-- Name: bot_profiles bot_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_profiles
    ADD CONSTRAINT bot_profiles_pkey PRIMARY KEY (tenant_id);


--
-- Name: bot_squads bot_squads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_squads
    ADD CONSTRAINT bot_squads_pkey PRIMARY KEY (tenant_id, source_uuid);


--
-- Name: bot_squads bot_squads_plan_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_squads
    ADD CONSTRAINT bot_squads_plan_id_key UNIQUE (plan_id);


--
-- Name: bot_subscription_aliases bot_subscription_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_subscription_aliases
    ADD CONSTRAINT bot_subscription_aliases_pkey PRIMARY KEY (alias);


--
-- Name: certificate_jobs certificate_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_jobs
    ADD CONSTRAINT certificate_jobs_pkey PRIMARY KEY (id);


--
-- Name: core_releases core_releases_identity_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.core_releases
    ADD CONSTRAINT core_releases_identity_unique UNIQUE (core_type, version, os, architecture);


--
-- Name: core_releases core_releases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.core_releases
    ADD CONSTRAINT core_releases_pkey PRIMARY KEY (id);


--
-- Name: deployment_execution_leases deployment_execution_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_execution_leases
    ADD CONSTRAINT deployment_execution_leases_pkey PRIMARY KEY (deployment_id);


--
-- Name: deployments deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_pkey PRIMARY KEY (id);


--
-- Name: desired_states desired_states_node_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.desired_states
    ADD CONSTRAINT desired_states_node_id_generation_key UNIQUE (node_id, generation);


--
-- Name: desired_states desired_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.desired_states
    ADD CONSTRAINT desired_states_pkey PRIMARY KEY (id);


--
-- Name: execution_fence_requests execution_fence_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_fence_requests
    ADD CONSTRAINT execution_fence_requests_pkey PRIMARY KEY (id);


--
-- Name: imported_subscription_external_accounts imported_subscription_external_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_external_accounts
    ADD CONSTRAINT imported_subscription_external_accounts_pkey PRIMARY KEY (revision_id, legacy_id);


--
-- Name: imported_subscription_host_services imported_subscription_host_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_host_services
    ADD CONSTRAINT imported_subscription_host_services_pkey PRIMARY KEY (revision_id, source_host_id, service_id);


--
-- Name: imported_subscription_profiles imported_subscription_profiles_import_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_profiles
    ADD CONSTRAINT imported_subscription_profiles_import_id_key UNIQUE (import_id);


--
-- Name: imported_subscription_profiles imported_subscription_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_profiles
    ADD CONSTRAINT imported_subscription_profiles_pkey PRIMARY KEY (tenant_id);


--
-- Name: imported_subscription_revisions imported_subscription_revisio_import_id_inventory_sha256_se_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisio_import_id_inventory_sha256_se_key UNIQUE (import_id, inventory_sha256, settings_sha256);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_id_tenant_id_import_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_id_tenant_id_import_id_key UNIQUE (id, tenant_id, import_id);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_id_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_id_tenant_id_key UNIQUE (id, tenant_id);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_pkey PRIMARY KEY (id);


--
-- Name: imported_subscription_squad_services imported_subscription_squad_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_squad_services
    ADD CONSTRAINT imported_subscription_squad_services_pkey PRIMARY KEY (revision_id, source_squad_id, service_id);


--
-- Name: imported_tls_certificates imported_tls_certificates_node_id_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_tls_certificates
    ADD CONSTRAINT imported_tls_certificates_node_id_domain_key UNIQUE (node_id, domain);


--
-- Name: imported_tls_certificates imported_tls_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_tls_certificates
    ADD CONSTRAINT imported_tls_certificates_pkey PRIMARY KEY (certificate_id);


--
-- Name: ingress_companions ingress_companions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_companions
    ADD CONSTRAINT ingress_companions_pkey PRIMARY KEY (node_id);


--
-- Name: ingress_provision_infrastructure ingress_provision_infrastructure_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_infrastructure
    ADD CONSTRAINT ingress_provision_infrastructure_pkey PRIMARY KEY (singleton);


--
-- Name: ingress_provision_runs ingress_provision_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_runs
    ADD CONSTRAINT ingress_provision_runs_pkey PRIMARY KEY (id);


--
-- Name: ingress_provision_runs ingress_provision_runs_request_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_runs
    ADD CONSTRAINT ingress_provision_runs_request_key_key UNIQUE (request_key);


--
-- Name: ingress_provision_tasks ingress_provision_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_tasks
    ADD CONSTRAINT ingress_provision_tasks_pkey PRIMARY KEY (id);


--
-- Name: ingress_provision_tasks ingress_provision_tasks_run_id_node_id_operation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_tasks
    ADD CONSTRAINT ingress_provision_tasks_run_id_node_id_operation_key UNIQUE (run_id, node_id, operation);


--
-- Name: monitoring_incidents monitoring_incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_incidents
    ADD CONSTRAINT monitoring_incidents_pkey PRIMARY KEY (id);


--
-- Name: monitoring_runs monitoring_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_runs
    ADD CONSTRAINT monitoring_runs_pkey PRIMARY KEY (id);


--
-- Name: node_backup_reports node_backup_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_backup_reports
    ADD CONSTRAINT node_backup_reports_pkey PRIMARY KEY (node_id);


--
-- Name: node_certificates node_certificates_id_tenant_node_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_id_tenant_node_unique UNIQUE (id, tenant_id, node_id);


--
-- Name: node_certificates node_certificates_native_identity_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_native_identity_unique UNIQUE (id, node_id, tenant_id);


--
-- Name: node_certificates node_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_pkey PRIMARY KEY (id);


--
-- Name: node_certificates node_certificates_ref_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_ref_unique UNIQUE (certificate_ref);


--
-- Name: node_client_traffic_cursors node_client_traffic_cursors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_client_traffic_cursors
    ADD CONSTRAINT node_client_traffic_cursors_pkey PRIMARY KEY (node_id, client_id);


--
-- Name: node_core_update_policies node_core_update_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_core_update_policies
    ADD CONSTRAINT node_core_update_policies_pkey PRIMARY KEY (node_id, core_type);


--
-- Name: node_health node_health_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_health
    ADD CONSTRAINT node_health_pkey PRIMARY KEY (node_id);


--
-- Name: node_ingress_policies node_ingress_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_ingress_policies
    ADD CONSTRAINT node_ingress_policies_pkey PRIMARY KEY (node_id);


--
-- Name: node_metric_samples node_metric_samples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_metric_samples
    ADD CONSTRAINT node_metric_samples_pkey PRIMARY KEY (node_id, sample_bucket);


--
-- Name: node_reboot_jobs node_reboot_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_reboot_jobs
    ADD CONSTRAINT node_reboot_jobs_pkey PRIMARY KEY (id);


--
-- Name: node_retirements node_retirements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_retirements
    ADD CONSTRAINT node_retirements_pkey PRIMARY KEY (node_id);


--
-- Name: node_security_policies node_security_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_security_policies
    ADD CONSTRAINT node_security_policies_pkey PRIMARY KEY (node_id);


--
-- Name: node_security_reports node_security_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_security_reports
    ADD CONSTRAINT node_security_reports_pkey PRIMARY KEY (node_id);


--
-- Name: node_traffic_delivery node_traffic_delivery_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_traffic_delivery
    ADD CONSTRAINT node_traffic_delivery_pkey PRIMARY KEY (node_id);


--
-- Name: node_xray_profile_bindings node_xray_profile_bindings_node_id_inbound_tag_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profile_bindings
    ADD CONSTRAINT node_xray_profile_bindings_node_id_inbound_tag_key UNIQUE (node_id, inbound_tag);


--
-- Name: node_xray_profile_bindings node_xray_profile_bindings_node_id_source_inbound_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profile_bindings
    ADD CONSTRAINT node_xray_profile_bindings_node_id_source_inbound_id_key UNIQUE (node_id, source_inbound_id);


--
-- Name: node_xray_profile_bindings node_xray_profile_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profile_bindings
    ADD CONSTRAINT node_xray_profile_bindings_pkey PRIMARY KEY (service_id);


--
-- Name: node_xray_profiles node_xray_profiles_import_id_source_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_import_id_source_node_id_key UNIQUE (import_id, source_node_id);


--
-- Name: node_xray_profiles node_xray_profiles_node_id_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_node_id_tenant_id_key UNIQUE (node_id, tenant_id);


--
-- Name: node_xray_profiles node_xray_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_pkey PRIMARY KEY (node_id);


--
-- Name: nodes nodes_id_tenant_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_id_tenant_unique UNIQUE (id, tenant_id);


--
-- Name: nodes nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (id);


--
-- Name: pauk_remnawave_quota_schedules pauk_remnawave_quota_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pauk_remnawave_quota_schedules
    ADD CONSTRAINT pauk_remnawave_quota_schedules_pkey PRIMARY KEY (client_id);


--
-- Name: platform_ingress_config platform_ingress_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_ingress_config
    ADD CONSTRAINT platform_ingress_config_pkey PRIMARY KEY (singleton);


--
-- Name: protocol_ingress_entry_nodes protocol_ingress_entry_nodes_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_entry_nodes
    ADD CONSTRAINT protocol_ingress_entry_nodes_address_key UNIQUE (address);


--
-- Name: protocol_ingress_entry_nodes protocol_ingress_entry_nodes_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_entry_nodes
    ADD CONSTRAINT protocol_ingress_entry_nodes_node_id_key UNIQUE (node_id);


--
-- Name: protocol_ingress_entry_nodes protocol_ingress_entry_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_entry_nodes
    ADD CONSTRAINT protocol_ingress_entry_nodes_pkey PRIMARY KEY (entry_id);


--
-- Name: protocol_ingress_ports protocol_ingress_ports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_ports
    ADD CONSTRAINT protocol_ingress_ports_pkey PRIMARY KEY (service_id);


--
-- Name: protocol_ingress_ports protocol_ingress_ports_port_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_ports
    ADD CONSTRAINT protocol_ingress_ports_port_key UNIQUE (port);


--
-- Name: protocol_ingress_reports protocol_ingress_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_reports
    ADD CONSTRAINT protocol_ingress_reports_pkey PRIMARY KEY (entry_id, service_id);


--
-- Name: protocol_template_installations protocol_template_installations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_template_installations
    ADD CONSTRAINT protocol_template_installations_pkey PRIMARY KEY (request_key);


--
-- Name: protocol_template_installations protocol_template_installations_service_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_template_installations
    ADD CONSTRAINT protocol_template_installations_service_id_key UNIQUE (service_id);


--
-- Name: recovery_attempts recovery_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_pkey PRIMARY KEY (id);


--
-- Name: remnawave_cutovers remnawave_cutovers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_cutovers
    ADD CONSTRAINT remnawave_cutovers_pkey PRIMARY KEY (import_id);


--
-- Name: remnawave_import_clients remnawave_import_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_clients
    ADD CONSTRAINT remnawave_import_clients_client_id_key UNIQUE (client_id);


--
-- Name: remnawave_import_clients remnawave_import_clients_deleted_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_clients
    ADD CONSTRAINT remnawave_import_clients_deleted_client_id_key UNIQUE (deleted_client_id);


--
-- Name: remnawave_import_clients remnawave_import_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_clients
    ADD CONSTRAINT remnawave_import_clients_pkey PRIMARY KEY (import_id, source_user_id);


--
-- Name: remnawave_import_heads remnawave_import_heads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_heads
    ADD CONSTRAINT remnawave_import_heads_pkey PRIMARY KEY (import_id);


--
-- Name: remnawave_imports remnawave_imports_id_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_imports
    ADD CONSTRAINT remnawave_imports_id_tenant_id_key UNIQUE (id, tenant_id);


--
-- Name: remnawave_imports remnawave_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_imports
    ADD CONSTRAINT remnawave_imports_pkey PRIMARY KEY (id);


--
-- Name: remnawave_imports remnawave_imports_source_origin_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_imports
    ADD CONSTRAINT remnawave_imports_source_origin_key UNIQUE (source_origin);


--
-- Name: remnawave_inventory_revisions remnawave_inventory_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_inventory_revisions
    ADD CONSTRAINT remnawave_inventory_revisions_pkey PRIMARY KEY (import_id, inventory_sha256);


--
-- Name: remnawave_inventory_revisions remnawave_inventory_revisions_sequence_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_inventory_revisions
    ADD CONSTRAINT remnawave_inventory_revisions_sequence_id_key UNIQUE (sequence_id);


--
-- Name: remnawave_subscription_settings remnawave_subscription_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_subscription_settings
    ADD CONSTRAINT remnawave_subscription_settings_pkey PRIMARY KEY (import_id, settings_sha256);


--
-- Name: reseller_children reseller_children_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_children
    ADD CONSTRAINT reseller_children_pkey PRIMARY KEY (child_tenant_id);


--
-- Name: rollout_plans rollout_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_pkey PRIMARY KEY (id);


--
-- Name: rollout_plans rollout_plans_request_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_request_key_key UNIQUE (request_key);


--
-- Name: service_ingress_policies service_ingress_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_ingress_policies
    ADD CONSTRAINT service_ingress_policies_pkey PRIMARY KEY (service_id);


--
-- Name: tenant_api_tokens tenant_api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_api_tokens
    ADD CONSTRAINT tenant_api_tokens_pkey PRIMARY KEY (id);


--
-- Name: tenant_api_tokens tenant_api_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_api_tokens
    ADD CONSTRAINT tenant_api_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: tenant_auto_profile_publications tenant_auto_profile_publications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_publications
    ADD CONSTRAINT tenant_auto_profile_publications_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_auto_profile_refresh_runs tenant_auto_profile_refresh_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_refresh_runs
    ADD CONSTRAINT tenant_auto_profile_refresh_runs_pkey PRIMARY KEY (id);


--
-- Name: tenant_auto_profile_refresh_runs tenant_auto_profile_refresh_runs_tenant_id_request_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_refresh_runs
    ADD CONSTRAINT tenant_auto_profile_refresh_runs_tenant_id_request_key_key UNIQUE (tenant_id, request_key);


--
-- Name: tenant_auto_profile_refresh_schedules tenant_auto_profile_refresh_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_refresh_schedules
    ADD CONSTRAINT tenant_auto_profile_refresh_schedules_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_auto_profiles tenant_auto_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profiles
    ADD CONSTRAINT tenant_auto_profiles_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_branding tenant_branding_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_branding
    ADD CONSTRAINT tenant_branding_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_resource_limits tenant_resource_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_resource_limits
    ADD CONSTRAINT tenant_resource_limits_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: vpn_access_plan_services vpn_access_plan_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plan_services
    ADD CONSTRAINT vpn_access_plan_services_pkey PRIMARY KEY (plan_id, service_id);


--
-- Name: vpn_access_plans vpn_access_plans_id_tenant_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plans
    ADD CONSTRAINT vpn_access_plans_id_tenant_unique UNIQUE (id, tenant_id);


--
-- Name: vpn_access_plans vpn_access_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plans
    ADD CONSTRAINT vpn_access_plans_pkey PRIMARY KEY (id);


--
-- Name: vpn_access_plans vpn_access_plans_tenant_code_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plans
    ADD CONSTRAINT vpn_access_plans_tenant_code_unique UNIQUE (tenant_id, code);


--
-- Name: vpn_cascades vpn_cascades_entry_node_id_entry_port_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_entry_node_id_entry_port_key UNIQUE (entry_node_id, entry_port);


--
-- Name: vpn_cascades vpn_cascades_id_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_id_tenant_id_key UNIQUE (id, tenant_id);


--
-- Name: vpn_cascades vpn_cascades_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_pkey PRIMARY KEY (id);


--
-- Name: vpn_cascades vpn_cascades_transit_uuid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_transit_uuid_key UNIQUE (transit_uuid);


--
-- Name: vpn_client_access_plans vpn_client_access_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_access_plans
    ADD CONSTRAINT vpn_client_access_plans_pkey PRIMARY KEY (client_id, plan_id);


--
-- Name: vpn_client_continuous_quotas vpn_client_continuous_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_continuous_quotas
    ADD CONSTRAINT vpn_client_continuous_quotas_pkey PRIMARY KEY (client_id);


--
-- Name: vpn_client_limits vpn_client_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_limits
    ADD CONSTRAINT vpn_client_limits_pkey PRIMARY KEY (client_id);


--
-- Name: vpn_client_openvpn_certificates vpn_client_openvpn_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_openvpn_certificates
    ADD CONSTRAINT vpn_client_openvpn_certificates_pkey PRIMARY KEY (service_id, serial);


--
-- Name: vpn_client_pptp vpn_client_pptp_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_pptp
    ADD CONSTRAINT vpn_client_pptp_pkey PRIMARY KEY (service_id, client_id);


--
-- Name: vpn_client_pptp vpn_client_pptp_service_id_address_index_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_pptp
    ADD CONSTRAINT vpn_client_pptp_service_id_address_index_key UNIQUE (service_id, address_index);


--
-- Name: vpn_client_services vpn_client_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_services
    ADD CONSTRAINT vpn_client_services_pkey PRIMARY KEY (client_id, service_id);


--
-- Name: vpn_client_shadowsocks_keys vpn_client_shadowsocks_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_shadowsocks_keys
    ADD CONSTRAINT vpn_client_shadowsocks_keys_pkey PRIMARY KEY (client_id, credential_uuid);


--
-- Name: vpn_client_subscriptions vpn_client_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_subscriptions
    ADD CONSTRAINT vpn_client_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: vpn_client_usage_monthly vpn_client_usage_monthly_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_usage_monthly
    ADD CONSTRAINT vpn_client_usage_monthly_pkey PRIMARY KEY (client_id, period_start);


--
-- Name: vpn_client_wireguard vpn_client_wireguard_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_wireguard
    ADD CONSTRAINT vpn_client_wireguard_pkey PRIMARY KEY (service_id, client_id);


--
-- Name: vpn_client_wireguard vpn_client_wireguard_service_id_address_index_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_wireguard
    ADD CONSTRAINT vpn_client_wireguard_service_id_address_index_key UNIQUE (service_id, address_index);


--
-- Name: vpn_clients vpn_clients_id_tenant_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_clients
    ADD CONSTRAINT vpn_clients_id_tenant_unique UNIQUE (id, tenant_id);


--
-- Name: vpn_clients vpn_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_clients
    ADD CONSTRAINT vpn_clients_pkey PRIMARY KEY (id);


--
-- Name: vpn_service_amneziawg vpn_service_amneziawg_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_amneziawg
    ADD CONSTRAINT vpn_service_amneziawg_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_openvpn vpn_service_openvpn_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_openvpn
    ADD CONSTRAINT vpn_service_openvpn_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_request_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_request_key_key UNIQUE (request_key);


--
-- Name: vpn_service_reality vpn_service_reality_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_reality
    ADD CONSTRAINT vpn_service_reality_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_reality vpn_service_reality_secret_ref_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_reality
    ADD CONSTRAINT vpn_service_reality_secret_ref_unique UNIQUE (secret_ref);


--
-- Name: vpn_service_shadowsocks vpn_service_shadowsocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_shadowsocks
    ADD CONSTRAINT vpn_service_shadowsocks_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_tls vpn_service_tls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_tls
    ADD CONSTRAINT vpn_service_tls_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_service_wireguard vpn_service_wireguard_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_wireguard
    ADD CONSTRAINT vpn_service_wireguard_pkey PRIMARY KEY (service_id);


--
-- Name: vpn_services vpn_services_id_tenant_node_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_services
    ADD CONSTRAINT vpn_services_id_tenant_node_unique UNIQUE (id, tenant_id, node_id);


--
-- Name: vpn_services vpn_services_id_tenant_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_services
    ADD CONSTRAINT vpn_services_id_tenant_unique UNIQUE (id, tenant_id);


--
-- Name: vpn_services vpn_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_services
    ADD CONSTRAINT vpn_services_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_endpoint_id_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_endpoint_id_event_id_key UNIQUE (endpoint_id, event_id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_dispatcher_runs webhook_dispatcher_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_dispatcher_runs
    ADD CONSTRAINT webhook_dispatcher_runs_pkey PRIMARY KEY (id);


--
-- Name: webhook_endpoints webhook_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id);


--
-- Name: admin_accounts_username_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX admin_accounts_username_key ON public.admin_accounts USING btree (lower(username));


--
-- Name: admin_sessions_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_sessions_account_idx ON public.admin_sessions USING btree (account_id);


--
-- Name: admin_sessions_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_sessions_expiry_idx ON public.admin_sessions USING btree (expires_at);


--
-- Name: agent_fleet_one_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX agent_fleet_one_claim ON public.agent_fleet_jobs USING btree ((true)) WHERE (status = 'claimed'::text);


--
-- Name: agent_fleet_one_open; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX agent_fleet_one_open ON public.agent_fleet_runs USING btree ((true)) WHERE (status = ANY (ARRAY['running'::text, 'paused'::text]));


--
-- Name: audit_events_created_cursor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_created_cursor_idx ON public.audit_events USING btree (created_at DESC, id DESC);


--
-- Name: audit_events_node_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_node_created_idx ON public.audit_events USING btree (node_id, created_at DESC);


--
-- Name: audit_events_stuck_episode_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX audit_events_stuck_episode_unique_idx ON public.audit_events USING btree (((payload ->> 'episode_key'::text))) WHERE ((event_type = 'deployment.stuck_detected'::text) AND (payload ? 'episode_key'::text));


--
-- Name: audit_events_tenant_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_tenant_created_idx ON public.audit_events USING btree (tenant_id, created_at DESC);


--
-- Name: audit_events_tenant_cursor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_tenant_cursor_idx ON public.audit_events USING btree (tenant_id, created_at DESC, id DESC);


--
-- Name: audit_events_type_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_type_created_idx ON public.audit_events USING btree (event_type, created_at DESC);


--
-- Name: audit_events_type_cursor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_type_cursor_idx ON public.audit_events USING btree (event_type, created_at DESC, id DESC);


--
-- Name: auto_profile_refresh_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auto_profile_refresh_due_idx ON public.tenant_auto_profile_refresh_schedules USING btree (next_run_at) WHERE enabled;


--
-- Name: auto_profile_refresh_history_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auto_profile_refresh_history_idx ON public.tenant_auto_profile_refresh_runs USING btree (tenant_id, checked_at DESC);


--
-- Name: auto_profile_refresh_slot_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX auto_profile_refresh_slot_idx ON public.tenant_auto_profile_refresh_runs USING btree (tenant_id, schedule_revision, scheduled_for) WHERE (origin = 'scheduled'::text);


--
-- Name: billing_entitlements_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX billing_entitlements_expiry_idx ON public.billing_entitlements USING btree (expires_at);


--
-- Name: billing_invoices_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX billing_invoices_tenant_idx ON public.billing_invoices USING btree (tenant_id, created_at DESC);


--
-- Name: billing_offers_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX billing_offers_tenant_idx ON public.billing_offers USING btree (tenant_id, created_at);


--
-- Name: billing_payment_reference_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX billing_payment_reference_unique ON public.billing_invoices USING btree (payment_reference) WHERE (status = 'paid'::text);


--
-- Name: bot_accounts_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX bot_accounts_email ON public.bot_accounts USING btree (tenant_id, email, legacy_id) WHERE (deleted_at IS NULL);


--
-- Name: bot_accounts_telegram; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX bot_accounts_telegram ON public.bot_accounts USING btree (tenant_id, telegram_id, legacy_id) WHERE (deleted_at IS NULL);


--
-- Name: bot_subscription_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX bot_subscription_one_active ON public.bot_subscription_aliases USING btree (tenant_id, legacy_id) WHERE (state = 'active'::text);


--
-- Name: certificate_jobs_certificate_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_jobs_certificate_idx ON public.certificate_jobs USING btree (certificate_id);


--
-- Name: certificate_jobs_lease_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_jobs_lease_idx ON public.certificate_jobs USING btree (lease_expires_at) WHERE (status = 'claimed'::text);


--
-- Name: certificate_jobs_node_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_jobs_node_status_idx ON public.certificate_jobs USING btree (node_id, status, created_at);


--
-- Name: certificate_jobs_one_active_per_certificate_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_jobs_one_active_per_certificate_uidx ON public.certificate_jobs USING btree (certificate_id) WHERE (status = ANY (ARRAY['pending'::text, 'claimed'::text]));


--
-- Name: core_releases_channel_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX core_releases_channel_idx ON public.core_releases USING btree (core_type, channel, os, architecture) WHERE ((approved = true) AND (revoked = false));


--
-- Name: core_releases_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX core_releases_lookup_idx ON public.core_releases USING btree (core_type, version, os, architecture);


--
-- Name: deployment_execution_leases_active_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX deployment_execution_leases_active_expiry_idx ON public.deployment_execution_leases USING btree (lease_expires_at, deployment_id) WHERE (state = 'active'::text);


--
-- Name: deployment_execution_leases_execution_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployment_execution_leases_execution_id_idx ON public.deployment_execution_leases USING btree (execution_id);


--
-- Name: deployment_execution_leases_node_epoch_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployment_execution_leases_node_epoch_idx ON public.deployment_execution_leases USING btree (node_id, execution_epoch);


--
-- Name: deployment_execution_leases_one_active_per_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployment_execution_leases_one_active_per_node_idx ON public.deployment_execution_leases USING btree (node_id) WHERE (state = 'active'::text);


--
-- Name: deployments_execution_id_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployments_execution_id_unique_idx ON public.deployments USING btree (execution_id);


--
-- Name: deployments_execution_identity_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployments_execution_identity_unique_idx ON public.deployments USING btree (id, node_id, generation, execution_id, execution_epoch);


--
-- Name: deployments_id_node_generation_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployments_id_node_generation_unique_idx ON public.deployments USING btree (id, node_id, generation);


--
-- Name: deployments_node_execution_epoch_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployments_node_execution_epoch_unique_idx ON public.deployments USING btree (node_id, execution_epoch);


--
-- Name: deployments_node_generation_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployments_node_generation_unique_idx ON public.deployments USING btree (node_id, generation);


--
-- Name: deployments_node_started_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX deployments_node_started_idx ON public.deployments USING btree (node_id, started_at DESC);


--
-- Name: deployments_nonterminal_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX deployments_nonterminal_updated_idx ON public.deployments USING btree (updated_at, id) WHERE (status = ANY (ARRAY['pending'::text, 'applying'::text]));


--
-- Name: deployments_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX deployments_status_idx ON public.deployments USING btree (status);


--
-- Name: execution_fence_requests_execution_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX execution_fence_requests_execution_idx ON public.execution_fence_requests USING btree (execution_id, execution_epoch);


--
-- Name: execution_fence_requests_node_requested_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX execution_fence_requests_node_requested_idx ON public.execution_fence_requests USING btree (node_id, requested_at) WHERE (state = 'requested'::text);


--
-- Name: execution_fence_requests_one_requested_execution_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX execution_fence_requests_one_requested_execution_idx ON public.execution_fence_requests USING btree (deployment_id) WHERE (state = 'requested'::text);


--
-- Name: hysteria_one_enabled_service; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX hysteria_one_enabled_service ON public.vpn_services USING btree (node_id) WHERE ((protocol = 'hysteria2'::text) AND enabled);


--
-- Name: ingress_one_provision_at_a_time; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ingress_one_provision_at_a_time ON public.ingress_provision_runs USING btree ((true)) WHERE (status = 'running'::text);


--
-- Name: ingress_tasks_by_node; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ingress_tasks_by_node ON public.ingress_provision_tasks USING btree (node_id, status);


--
-- Name: monitoring_active_condition_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX monitoring_active_condition_unique ON public.monitoring_incidents USING btree (rule, resource) WHERE (resolved_at IS NULL);


--
-- Name: monitoring_incidents_history_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX monitoring_incidents_history_idx ON public.monitoring_incidents USING btree (opened_at DESC) WHERE (opened_at IS NOT NULL);


--
-- Name: node_certificates_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_certificates_expiry_idx ON public.node_certificates USING btree (not_after) WHERE (not_after IS NOT NULL);


--
-- Name: node_certificates_node_domain_active_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX node_certificates_node_domain_active_uidx ON public.node_certificates USING btree (node_id, domain) WHERE (status <> ALL (ARRAY['revoked'::text, 'deleted'::text]));


--
-- Name: node_certificates_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_certificates_node_idx ON public.node_certificates USING btree (node_id);


--
-- Name: node_certificates_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_certificates_status_idx ON public.node_certificates USING btree (status);


--
-- Name: node_certificates_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_certificates_tenant_idx ON public.node_certificates USING btree (tenant_id);


--
-- Name: node_client_traffic_cursors_observed_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_client_traffic_cursors_observed_idx ON public.node_client_traffic_cursors USING btree (observed_at);


--
-- Name: node_client_traffic_last_online_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_client_traffic_last_online_idx ON public.node_client_traffic_cursors USING btree (client_id, last_online_at DESC) WHERE (last_online_at IS NOT NULL);


--
-- Name: node_core_update_policies_policy_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_core_update_policies_policy_idx ON public.node_core_update_policies USING btree (core_type, policy);


--
-- Name: node_metric_samples_node_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_metric_samples_node_time_idx ON public.node_metric_samples USING btree (node_id, sampled_at);


--
-- Name: node_metric_samples_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_metric_samples_time_idx ON public.node_metric_samples USING btree (sampled_at DESC);


--
-- Name: node_reboot_jobs_node_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX node_reboot_jobs_node_created_idx ON public.node_reboot_jobs USING btree (node_id, created_at DESC);


--
-- Name: node_reboot_jobs_one_active_per_node_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX node_reboot_jobs_one_active_per_node_uidx ON public.node_reboot_jobs USING btree (node_id) WHERE (status = ANY (ARRAY['queued'::text, 'claimed'::text]));


--
-- Name: nodes_agent_token_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX nodes_agent_token_hash_idx ON public.nodes USING btree (agent_token_hash) WHERE (agent_token_hash IS NOT NULL);


--
-- Name: nodes_bootstrap_token_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX nodes_bootstrap_token_hash_idx ON public.nodes USING btree (bootstrap_token_hash) WHERE (bootstrap_token_hash IS NOT NULL);


--
-- Name: nodes_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX nodes_tenant_idx ON public.nodes USING btree (tenant_id);


--
-- Name: nodes_tenant_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX nodes_tenant_name_unique ON public.nodes USING btree (tenant_id, name) WHERE (status <> 'retired'::text);


--
-- Name: openvpn_client_certificate_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX openvpn_client_certificate_lookup ON public.vpn_client_openvpn_certificates USING btree (service_id, client_id, credential_uuid, created_at DESC);


--
-- Name: openvpn_one_enabled_service; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX openvpn_one_enabled_service ON public.vpn_services USING btree (node_id) WHERE ((protocol = 'openvpn'::text) AND enabled);


--
-- Name: pauk_remnawave_quota_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pauk_remnawave_quota_due_idx ON public.pauk_remnawave_quota_schedules USING btree (next_reset_at, client_id);


--
-- Name: protocol_template_installations_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX protocol_template_installations_node_idx ON public.protocol_template_installations USING btree (node_id, created_at DESC);


--
-- Name: recovery_attempts_deployment_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX recovery_attempts_deployment_unique_idx ON public.recovery_attempts USING btree (deployment_id) WHERE (deployment_id IS NOT NULL);


--
-- Name: recovery_attempts_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recovery_attempts_expiry_idx ON public.recovery_attempts USING btree (expires_at) WHERE (status = ANY (ARRAY['planned'::text, 'approved'::text]));


--
-- Name: recovery_attempts_node_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recovery_attempts_node_created_idx ON public.recovery_attempts USING btree (node_id, created_at DESC);


--
-- Name: recovery_attempts_one_active_per_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX recovery_attempts_one_active_per_node_idx ON public.recovery_attempts USING btree (node_id) WHERE (status = ANY (ARRAY['planned'::text, 'approved'::text]));


--
-- Name: recovery_attempts_one_active_per_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX recovery_attempts_one_active_per_source_idx ON public.recovery_attempts USING btree (source_deployment_id) WHERE (status = ANY (ARRAY['planned'::text, 'approved'::text]));


--
-- Name: recovery_attempts_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recovery_attempts_status_idx ON public.recovery_attempts USING btree (status);


--
-- Name: recovery_attempts_target_release_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recovery_attempts_target_release_idx ON public.recovery_attempts USING btree (target_core_release_id) WHERE (target_core_release_id IS NOT NULL);


--
-- Name: reseller_children_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX reseller_children_parent_idx ON public.reseller_children USING btree (parent_tenant_id);


--
-- Name: rollout_plans_active_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rollout_plans_active_expiry_idx ON public.rollout_plans USING btree (expires_at) WHERE (status = ANY (ARRAY['planned'::text, 'approved'::text]));


--
-- Name: rollout_plans_deployment_id_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX rollout_plans_deployment_id_unique_idx ON public.rollout_plans USING btree (deployment_id) WHERE (deployment_id IS NOT NULL);


--
-- Name: rollout_plans_node_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rollout_plans_node_created_idx ON public.rollout_plans USING btree (node_id, created_at DESC);


--
-- Name: rollout_plans_one_active_per_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX rollout_plans_one_active_per_node_idx ON public.rollout_plans USING btree (node_id) WHERE (status = ANY (ARRAY['planned'::text, 'approved'::text]));


--
-- Name: rollout_plans_outcome_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rollout_plans_outcome_status_idx ON public.rollout_plans USING btree (outcome_status) WHERE (status = 'executed'::text);


--
-- Name: rollout_plans_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rollout_plans_status_idx ON public.rollout_plans USING btree (status);


--
-- Name: rollout_plans_target_release_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rollout_plans_target_release_idx ON public.rollout_plans USING btree (target_core_release_id) WHERE (target_core_release_id IS NOT NULL);


--
-- Name: tenant_api_tokens_issuer_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenant_api_tokens_issuer_idx ON public.tenant_api_tokens USING btree (issued_by_token_id) WHERE (issued_by_token_id IS NOT NULL);


--
-- Name: tenant_api_tokens_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenant_api_tokens_tenant_idx ON public.tenant_api_tokens USING btree (tenant_id, created_at);


--
-- Name: vpn_access_plan_services_service_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_access_plan_services_service_idx ON public.vpn_access_plan_services USING btree (service_id);


--
-- Name: vpn_access_plan_services_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_access_plan_services_tenant_idx ON public.vpn_access_plan_services USING btree (tenant_id);


--
-- Name: vpn_access_plans_enabled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_access_plans_enabled_idx ON public.vpn_access_plans USING btree (tenant_id, enabled);


--
-- Name: vpn_access_plans_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_access_plans_tenant_idx ON public.vpn_access_plans USING btree (tenant_id);


--
-- Name: vpn_cascade_client_dial_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_cascade_client_dial_idx ON public.vpn_cascades USING btree (tenant_id, exit_node_id) WHERE (connect_race_clients AND enabled AND (connect_race_attempts > 0));


--
-- Name: vpn_cascades_exit_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_cascades_exit_idx ON public.vpn_cascades USING btree (exit_node_id);


--
-- Name: vpn_cascades_plan_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_cascades_plan_idx ON public.vpn_cascades USING btree (plan_id);


--
-- Name: vpn_client_access_plans_plan_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_access_plans_plan_idx ON public.vpn_client_access_plans USING btree (plan_id);


--
-- Name: vpn_client_access_plans_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_access_plans_tenant_idx ON public.vpn_client_access_plans USING btree (tenant_id);


--
-- Name: vpn_client_services_service_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_services_service_idx ON public.vpn_client_services USING btree (service_id);


--
-- Name: vpn_client_services_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_services_tenant_idx ON public.vpn_client_services USING btree (tenant_id);


--
-- Name: vpn_client_subscriptions_client_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_subscriptions_client_idx ON public.vpn_client_subscriptions USING btree (client_id);


--
-- Name: vpn_client_subscriptions_one_active_per_client_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_client_subscriptions_one_active_per_client_uidx ON public.vpn_client_subscriptions USING btree (client_id) WHERE (status = 'active'::text);


--
-- Name: vpn_client_subscriptions_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_client_subscriptions_tenant_idx ON public.vpn_client_subscriptions USING btree (tenant_id);


--
-- Name: vpn_client_subscriptions_token_hash_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_client_subscriptions_token_hash_uidx ON public.vpn_client_subscriptions USING btree (token_hash);


--
-- Name: vpn_client_subscriptions_token_id_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_client_subscriptions_token_id_uidx ON public.vpn_client_subscriptions USING btree (token_id);


--
-- Name: vpn_clients_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_clients_expiry_idx ON public.vpn_clients USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: vpn_clients_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_clients_tenant_idx ON public.vpn_clients USING btree (tenant_id);


--
-- Name: vpn_clients_vless_uuid_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_clients_vless_uuid_uidx ON public.vpn_clients USING btree (vless_uuid);


--
-- Name: vpn_service_reality_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_service_reality_tenant_idx ON public.vpn_service_reality USING btree (tenant_id);


--
-- Name: vpn_service_tls_certificate_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_service_tls_certificate_idx ON public.vpn_service_tls USING btree (certificate_id);


--
-- Name: vpn_services_node_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_services_node_idx ON public.vpn_services USING btree (node_id);


--
-- Name: vpn_services_tcp_bind_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_services_tcp_bind_unique ON public.vpn_services USING btree (node_id, listen, port) WHERE (transport <> 'udp'::text);


--
-- Name: vpn_services_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vpn_services_tenant_idx ON public.vpn_services USING btree (tenant_id);


--
-- Name: vpn_services_udp_bind_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vpn_services_udp_bind_unique ON public.vpn_services USING btree (node_id, listen, port) WHERE (transport <> ALL (ARRAY['tcp'::text, 'raw'::text, 'xhttp'::text, 'ws'::text, 'grpc'::text, 'tcp,gre'::text]));


--
-- Name: webhook_deliveries_failed_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_failed_idx ON public.webhook_deliveries USING btree (endpoint_id) WHERE (status = 'failed'::text);


--
-- Name: webhook_deliveries_queue_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_queue_idx ON public.webhook_deliveries USING btree (next_attempt_at) WHERE (status = ANY (ARRAY['pending'::text, 'delivering'::text]));


--
-- Name: webhook_endpoints_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_endpoints_tenant_idx ON public.webhook_endpoints USING btree (tenant_id);


--
-- Name: clients native_clients_immutable; Type: TRIGGER; Schema: pauk_native_cutover; Owner: -
--

CREATE TRIGGER native_clients_immutable BEFORE DELETE OR UPDATE ON pauk_native_cutover.clients FOR EACH ROW EXECUTE FUNCTION pauk_native_cutover.immutable();


--
-- Name: events native_events_immutable; Type: TRIGGER; Schema: pauk_native_cutover; Owner: -
--

CREATE TRIGGER native_events_immutable BEFORE DELETE OR UPDATE ON pauk_native_cutover.events FOR EACH ROW EXECUTE FUNCTION pauk_native_cutover.immutable();


--
-- Name: nodes native_nodes_immutable; Type: TRIGGER; Schema: pauk_native_cutover; Owner: -
--

CREATE TRIGGER native_nodes_immutable BEFORE DELETE OR UPDATE ON pauk_native_cutover.nodes FOR EACH ROW EXECUTE FUNCTION pauk_native_cutover.immutable();


--
-- Name: vpn_access_plan_services access_plan_service_node_admission; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER access_plan_service_node_admission BEFORE INSERT OR UPDATE ON public.vpn_access_plan_services FOR EACH ROW EXECUTE FUNCTION public.reject_removed_node_group_service();


--
-- Name: agent_releases agent_release_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_release_identity BEFORE UPDATE ON public.agent_releases FOR EACH ROW EXECUTE FUNCTION public.protect_agent_release_identity();


--
-- Name: vpn_service_amneziawg amneziawg_settings_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER amneziawg_settings_identity BEFORE INSERT OR UPDATE ON public.vpn_service_amneziawg FOR EACH ROW EXECUTE FUNCTION public.enforce_amneziawg_settings_identity();


--
-- Name: audit_events billing_webhook_outbox; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER billing_webhook_outbox AFTER INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.enqueue_billing_webhook();


--
-- Name: vpn_clients bot_client_deletion; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bot_client_deletion BEFORE DELETE ON public.vpn_clients FOR EACH ROW EXECUTE FUNCTION public.bot_client_deleted();


--
-- Name: bot_profiles bot_profile_origin_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bot_profile_origin_immutable BEFORE UPDATE OF profile_kind, import_id ON public.bot_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_bot_profile_origin();


--
-- Name: deployment_execution_leases deployment_execution_lease_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deployment_execution_lease_transition_guard BEFORE UPDATE OF state ON public.deployment_execution_leases FOR EACH ROW WHEN ((old.state IS DISTINCT FROM new.state)) EXECUTE FUNCTION public.vpn_platform_guard_execution_lease_transition();


--
-- Name: deployments deployments_execution_identity_assign; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deployments_execution_identity_assign BEFORE INSERT ON public.deployments FOR EACH ROW EXECUTE FUNCTION public.vpn_platform_assign_deployment_execution_identity();


--
-- Name: deployments deployments_execution_identity_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deployments_execution_identity_guard BEFORE UPDATE OF execution_id, execution_epoch ON public.deployments FOR EACH ROW EXECUTE FUNCTION public.vpn_platform_guard_execution_identity();


--
-- Name: deployments deployments_status_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deployments_status_transition_guard BEFORE UPDATE OF status ON public.deployments FOR EACH ROW WHEN ((old.status IS DISTINCT FROM new.status)) EXECUTE FUNCTION public.vpn_platform_guard_deployment_transition();


--
-- Name: desired_states desired_runtime_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER desired_runtime_identity BEFORE INSERT OR UPDATE OF document, node_id ON public.desired_states FOR EACH ROW EXECUTE FUNCTION public.enforce_desired_runtime_identity();


--
-- Name: execution_fence_requests execution_fence_request_identity_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER execution_fence_request_identity_guard BEFORE UPDATE ON public.execution_fence_requests FOR EACH ROW EXECUTE FUNCTION public.vpn_platform_guard_execution_fence_request_identity();


--
-- Name: execution_fence_requests execution_fence_request_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER execution_fence_request_transition_guard BEFORE UPDATE OF state ON public.execution_fence_requests FOR EACH ROW WHEN ((old.state IS DISTINCT FROM new.state)) EXECUTE FUNCTION public.vpn_platform_guard_execution_fence_request_transition();


--
-- Name: vpn_service_reality imported_reality_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_reality_identity BEFORE INSERT OR UPDATE ON public.vpn_service_reality FOR EACH ROW EXECUTE FUNCTION public.enforce_imported_reality_identity();


--
-- Name: vpn_services imported_service_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_service_identity BEFORE INSERT OR UPDATE ON public.vpn_services FOR EACH ROW EXECUTE FUNCTION public.enforce_imported_service_identity();


--
-- Name: remnawave_subscription_settings imported_settings_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_settings_immutable BEFORE DELETE OR UPDATE ON public.remnawave_subscription_settings FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: imported_subscription_external_accounts imported_subscription_external_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_subscription_external_immutable BEFORE DELETE OR UPDATE ON public.imported_subscription_external_accounts FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: imported_subscription_profiles imported_subscription_head_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_subscription_head_identity BEFORE UPDATE ON public.imported_subscription_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_imported_subscription_head();


--
-- Name: imported_subscription_host_services imported_subscription_host_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_subscription_host_immutable BEFORE DELETE OR UPDATE ON public.imported_subscription_host_services FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: imported_subscription_revisions imported_subscription_revision_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_subscription_revision_immutable BEFORE DELETE OR UPDATE ON public.imported_subscription_revisions FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: imported_subscription_squad_services imported_subscription_squad_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_subscription_squad_immutable BEFORE DELETE OR UPDATE ON public.imported_subscription_squad_services FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: node_certificates imported_tls_certificate_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_tls_certificate_guard BEFORE UPDATE ON public.node_certificates FOR EACH ROW EXECUTE FUNCTION public.guard_imported_tls_certificate();


--
-- Name: certificate_jobs imported_tls_job_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_tls_job_guard BEFORE INSERT OR UPDATE OF certificate_id, node_id, tenant_id, status ON public.certificate_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_imported_tls_job();


--
-- Name: imported_tls_certificates imported_tls_provenance_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER imported_tls_provenance_immutable BEFORE DELETE OR UPDATE ON public.imported_tls_certificates FOR EACH ROW EXECUTE FUNCTION public.immutable_xray_profile();


--
-- Name: remnawave_cutovers native_capture_begin; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER native_capture_begin AFTER INSERT ON public.remnawave_cutovers FOR EACH ROW EXECUTE FUNCTION pauk_native_cutover.begin_capture();


--
-- Name: remnawave_cutovers native_capture_published; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER native_capture_published AFTER UPDATE OF state ON public.remnawave_cutovers FOR EACH ROW WHEN ((new.state IS DISTINCT FROM old.state)) EXECUTE FUNCTION pauk_native_cutover.published();


--
-- Name: node_client_traffic_cursors native_capture_traffic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER native_capture_traffic AFTER INSERT OR UPDATE ON public.node_client_traffic_cursors FOR EACH ROW EXECUTE FUNCTION pauk_native_cutover.capture();


--
-- Name: nodes node_group_services_removed; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER node_group_services_removed AFTER UPDATE OF status ON public.nodes FOR EACH ROW EXECUTE FUNCTION public.detach_removed_node_group_services();


--
-- Name: node_retirements node_retirement_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER node_retirement_immutable BEFORE DELETE OR UPDATE ON public.node_retirements FOR EACH ROW EXECUTE FUNCTION public.protect_node_retirement();


--
-- Name: nodes node_runtime_identity_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER node_runtime_identity_immutable BEFORE UPDATE OF runtime_core ON public.nodes FOR EACH ROW EXECUTE FUNCTION public.protect_node_runtime_identity();


--
-- Name: vpn_client_continuous_quotas pauk_remnawave_ignore_late_traffic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER pauk_remnawave_ignore_late_traffic BEFORE UPDATE OF uplink_bytes, downlink_bytes ON public.vpn_client_continuous_quotas FOR EACH ROW EXECUTE FUNCTION public.pauk_remnawave_ignore_late_traffic();


--
-- Name: node_client_traffic_cursors pauk_remnawave_observe_traffic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER pauk_remnawave_observe_traffic AFTER INSERT OR UPDATE ON public.node_client_traffic_cursors FOR EACH ROW EXECUTE FUNCTION public.pauk_remnawave_observe_traffic();


--
-- Name: vpn_services protocol_ingress_port_new_service; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protocol_ingress_port_new_service AFTER INSERT ON public.vpn_services FOR EACH ROW EXECUTE FUNCTION public.allocate_protocol_ingress_port();


--
-- Name: vpn_service_protocol_templates protocol_template_binding; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protocol_template_binding BEFORE INSERT OR UPDATE ON public.vpn_service_protocol_templates FOR EACH ROW EXECUTE FUNCTION public.enforce_protocol_template_binding();


--
-- Name: bot_devices registered_device_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER registered_device_owner BEFORE INSERT OR UPDATE OF tenant_id, legacy_id, client_id ON public.bot_devices FOR EACH ROW EXECUTE FUNCTION public.resolve_registered_device_owner();


--
-- Name: agent_fleet_jobs reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.agent_fleet_jobs FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: agent_updaters reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.agent_updaters FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: certificate_jobs reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.certificate_jobs FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: deployment_execution_leases reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.deployment_execution_leases FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: deployments reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.deployments FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: desired_states reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.desired_states FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: execution_fence_requests reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.execution_fence_requests FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: node_certificates reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.node_certificates FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: node_core_update_policies reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.node_core_update_policies FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: node_health reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.node_health FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: recovery_attempts reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.recovery_attempts FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: rollout_plans reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.rollout_plans FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: vpn_services reject_retired_work; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON public.vpn_services FOR EACH ROW EXECUTE FUNCTION public.reject_retired_node_work();


--
-- Name: remnawave_cutovers remnawave_cutover_identity_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER remnawave_cutover_identity_immutable BEFORE UPDATE OF import_id, tenant_id, request_sha256, inventory_sha256, subscription_revision_id, request, result ON public.remnawave_cutovers FOR EACH ROW EXECUTE FUNCTION public.immutable_xray_profile();


--
-- Name: remnawave_imports remnawave_initial_revision; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER remnawave_initial_revision AFTER INSERT ON public.remnawave_imports FOR EACH ROW EXECUTE FUNCTION public.remnawave_record_initial_revision();


--
-- Name: remnawave_imports remnawave_original_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER remnawave_original_immutable BEFORE UPDATE OF source_origin, inventory_sha256, inventory, report, user_count, captured_at ON public.remnawave_imports FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: remnawave_inventory_revisions remnawave_revision_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER remnawave_revision_immutable BEFORE UPDATE ON public.remnawave_inventory_revisions FOR EACH ROW EXECUTE FUNCTION public.remnawave_reject_inventory_update();


--
-- Name: nodes retired_node_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER retired_node_immutable BEFORE DELETE OR UPDATE ON public.nodes FOR EACH ROW EXECUTE FUNCTION public.protect_retired_node();


--
-- Name: rollout_plans rollout_outcome_transition_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER rollout_outcome_transition_guard BEFORE UPDATE OF outcome_status ON public.rollout_plans FOR EACH ROW WHEN ((old.outcome_status IS DISTINCT FROM new.outcome_status)) EXECUTE FUNCTION public.vpn_platform_guard_rollout_outcome_transition();


--
-- Name: vpn_services service_runtime_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER service_runtime_identity BEFORE INSERT OR UPDATE OF node_id, protocol, transport, security ON public.vpn_services FOR EACH ROW EXECUTE FUNCTION public.enforce_service_runtime_identity();


--
-- Name: node_xray_profiles xray_activation_monotonic; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER xray_activation_monotonic BEFORE UPDATE OF state ON public.node_xray_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_xray_activation_monotonic();


--
-- Name: node_xray_profile_bindings xray_binding_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER xray_binding_immutable BEFORE DELETE OR UPDATE ON public.node_xray_profile_bindings FOR EACH ROW EXECUTE FUNCTION public.immutable_xray_profile();


--
-- Name: node_xray_profiles xray_profile_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER xray_profile_immutable BEFORE UPDATE OF node_id, tenant_id, import_id, inventory_sha256, source_node_id, source_profile_id, profile_sha256, profile ON public.node_xray_profiles FOR EACH ROW EXECUTE FUNCTION public.immutable_xray_profile();


--
-- Name: clients clients_import_id_fkey; Type: FK CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.clients
    ADD CONSTRAINT clients_import_id_fkey FOREIGN KEY (import_id) REFERENCES pauk_native_cutover.sessions(import_id);


--
-- Name: events events_import_id_client_id_fkey; Type: FK CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.events
    ADD CONSTRAINT events_import_id_client_id_fkey FOREIGN KEY (import_id, client_id) REFERENCES pauk_native_cutover.clients(import_id, client_id);


--
-- Name: events events_import_id_node_id_fkey; Type: FK CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.events
    ADD CONSTRAINT events_import_id_node_id_fkey FOREIGN KEY (import_id, node_id) REFERENCES pauk_native_cutover.nodes(import_id, node_id);


--
-- Name: nodes nodes_import_id_fkey; Type: FK CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.nodes
    ADD CONSTRAINT nodes_import_id_fkey FOREIGN KEY (import_id) REFERENCES pauk_native_cutover.sessions(import_id);


--
-- Name: sessions sessions_import_id_fkey; Type: FK CONSTRAINT; Schema: pauk_native_cutover; Owner: -
--

ALTER TABLE ONLY pauk_native_cutover.sessions
    ADD CONSTRAINT sessions_import_id_fkey FOREIGN KEY (import_id) REFERENCES public.remnawave_cutovers(import_id);


--
-- Name: admin_mfa admin_mfa_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_mfa
    ADD CONSTRAINT admin_mfa_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.admin_accounts(id) ON DELETE CASCADE;


--
-- Name: admin_sessions admin_sessions_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.admin_accounts(id) ON DELETE CASCADE;


--
-- Name: agent_fleet_attempts agent_fleet_attempts_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_attempts
    ADD CONSTRAINT agent_fleet_attempts_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.agent_fleet_jobs(id) ON DELETE CASCADE;


--
-- Name: agent_fleet_jobs agent_fleet_jobs_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_jobs
    ADD CONSTRAINT agent_fleet_jobs_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: agent_fleet_jobs agent_fleet_jobs_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_jobs
    ADD CONSTRAINT agent_fleet_jobs_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.agent_fleet_runs(id) ON DELETE CASCADE;


--
-- Name: agent_fleet_policy agent_fleet_policy_target_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_policy
    ADD CONSTRAINT agent_fleet_policy_target_version_fkey FOREIGN KEY (target_version) REFERENCES public.agent_releases(version);


--
-- Name: agent_fleet_runs agent_fleet_runs_origin_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_runs
    ADD CONSTRAINT agent_fleet_runs_origin_node_id_fkey FOREIGN KEY (origin_node_id) REFERENCES public.nodes(id) ON DELETE SET NULL;


--
-- Name: agent_fleet_runs agent_fleet_runs_priority_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_runs
    ADD CONSTRAINT agent_fleet_runs_priority_node_id_fkey FOREIGN KEY (priority_node_id) REFERENCES public.nodes(id) ON DELETE SET NULL;


--
-- Name: agent_fleet_runs agent_fleet_runs_target_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_fleet_runs
    ADD CONSTRAINT agent_fleet_runs_target_version_fkey FOREIGN KEY (target_version) REFERENCES public.agent_releases(version);


--
-- Name: agent_updaters agent_updaters_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_updaters
    ADD CONSTRAINT agent_updaters_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: audit_events audit_events_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: audit_events audit_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: billing_entitlements billing_entitlements_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_entitlements
    ADD CONSTRAINT billing_entitlements_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: billing_entitlements billing_entitlements_plan_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_entitlements
    ADD CONSTRAINT billing_entitlements_plan_id_tenant_id_fkey FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id) ON DELETE CASCADE;


--
-- Name: billing_entitlements billing_entitlements_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_entitlements
    ADD CONSTRAINT billing_entitlements_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: billing_invoices billing_invoice_live_client_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoice_live_client_fk FOREIGN KEY (live_client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id);


--
-- Name: billing_invoices billing_invoices_offer_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_offer_id_tenant_id_fkey FOREIGN KEY (offer_id, tenant_id) REFERENCES public.billing_offers(id, tenant_id);


--
-- Name: billing_invoices billing_invoices_plan_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_plan_id_tenant_id_fkey FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id);


--
-- Name: billing_invoices billing_invoices_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: billing_offers billing_offers_plan_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_offers
    ADD CONSTRAINT billing_offers_plan_id_tenant_id_fkey FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id);


--
-- Name: billing_offers billing_offers_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_offers
    ADD CONSTRAINT billing_offers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: billing_payment_events billing_payment_events_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_payment_events
    ADD CONSTRAINT billing_payment_events_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.billing_invoices(id) ON DELETE CASCADE;


--
-- Name: bot_account_squads bot_account_squads_tenant_id_legacy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_account_squads
    ADD CONSTRAINT bot_account_squads_tenant_id_legacy_id_fkey FOREIGN KEY (tenant_id, legacy_id) REFERENCES public.bot_accounts(tenant_id, legacy_id) ON DELETE CASCADE;


--
-- Name: bot_account_squads bot_account_squads_tenant_id_source_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_account_squads
    ADD CONSTRAINT bot_account_squads_tenant_id_source_uuid_fkey FOREIGN KEY (tenant_id, source_uuid) REFERENCES public.bot_squads(tenant_id, source_uuid);


--
-- Name: bot_accounts bot_accounts_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_accounts
    ADD CONSTRAINT bot_accounts_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: bot_accounts bot_accounts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_accounts
    ADD CONSTRAINT bot_accounts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.bot_profiles(tenant_id);


--
-- Name: bot_devices bot_devices_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_devices
    ADD CONSTRAINT bot_devices_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: bot_devices bot_devices_tenant_id_legacy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_devices
    ADD CONSTRAINT bot_devices_tenant_id_legacy_id_fkey FOREIGN KEY (tenant_id, legacy_id) REFERENCES public.bot_accounts(tenant_id, legacy_id) ON DELETE CASCADE;


--
-- Name: bot_operations bot_operations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_operations
    ADD CONSTRAINT bot_operations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.bot_profiles(tenant_id);


--
-- Name: bot_profiles bot_profiles_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_profiles
    ADD CONSTRAINT bot_profiles_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256);


--
-- Name: bot_profiles bot_profiles_import_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_profiles
    ADD CONSTRAINT bot_profiles_import_id_tenant_id_fkey FOREIGN KEY (import_id, tenant_id) REFERENCES public.remnawave_imports(id, tenant_id);


--
-- Name: bot_profiles bot_profiles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_profiles
    ADD CONSTRAINT bot_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: bot_squads bot_squads_plan_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_squads
    ADD CONSTRAINT bot_squads_plan_id_tenant_id_fkey FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: bot_squads bot_squads_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_squads
    ADD CONSTRAINT bot_squads_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.bot_profiles(tenant_id);


--
-- Name: bot_subscription_aliases bot_subscription_aliases_tenant_id_legacy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_subscription_aliases
    ADD CONSTRAINT bot_subscription_aliases_tenant_id_legacy_id_fkey FOREIGN KEY (tenant_id, legacy_id) REFERENCES public.bot_accounts(tenant_id, legacy_id);


--
-- Name: certificate_jobs certificate_jobs_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_jobs
    ADD CONSTRAINT certificate_jobs_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.node_certificates(id) ON DELETE CASCADE;


--
-- Name: certificate_jobs certificate_jobs_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_jobs
    ADD CONSTRAINT certificate_jobs_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: certificate_jobs certificate_jobs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_jobs
    ADD CONSTRAINT certificate_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: deployment_execution_leases deployment_execution_leases_exact_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_execution_leases
    ADD CONSTRAINT deployment_execution_leases_exact_fk FOREIGN KEY (deployment_id, node_id, generation, execution_id, execution_epoch) REFERENCES public.deployments(id, node_id, generation, execution_id, execution_epoch) ON DELETE CASCADE;


--
-- Name: deployments deployments_core_release_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_core_release_id_fkey FOREIGN KEY (core_release_id) REFERENCES public.core_releases(id);


--
-- Name: deployments deployments_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: desired_states desired_states_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.desired_states
    ADD CONSTRAINT desired_states_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: execution_fence_requests execution_fence_requests_exact_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_fence_requests
    ADD CONSTRAINT execution_fence_requests_exact_fk FOREIGN KEY (deployment_id, node_id, generation, execution_id, execution_epoch) REFERENCES public.deployments(id, node_id, generation, execution_id, execution_epoch) ON DELETE CASCADE;


--
-- Name: execution_fence_requests execution_fence_requests_node_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_fence_requests
    ADD CONSTRAINT execution_fence_requests_node_fk FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: execution_fence_requests execution_fence_requests_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_fence_requests
    ADD CONSTRAINT execution_fence_requests_tenant_fk FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: imported_subscription_external_accounts imported_subscription_external_accou_revision_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_external_accounts
    ADD CONSTRAINT imported_subscription_external_accou_revision_id_tenant_id_fkey FOREIGN KEY (revision_id, tenant_id) REFERENCES public.imported_subscription_revisions(id, tenant_id);


--
-- Name: imported_subscription_external_accounts imported_subscription_external_account_tenant_id_legacy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_external_accounts
    ADD CONSTRAINT imported_subscription_external_account_tenant_id_legacy_id_fkey FOREIGN KEY (tenant_id, legacy_id) REFERENCES public.bot_accounts(tenant_id, legacy_id);


--
-- Name: imported_subscription_host_services imported_subscription_host_services_revision_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_host_services
    ADD CONSTRAINT imported_subscription_host_services_revision_id_tenant_id_fkey FOREIGN KEY (revision_id, tenant_id) REFERENCES public.imported_subscription_revisions(id, tenant_id);


--
-- Name: imported_subscription_host_services imported_subscription_host_services_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_host_services
    ADD CONSTRAINT imported_subscription_host_services_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id);


--
-- Name: imported_subscription_profiles imported_subscription_profile_revision_id_tenant_id_import_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_profiles
    ADD CONSTRAINT imported_subscription_profile_revision_id_tenant_id_import_fkey FOREIGN KEY (revision_id, tenant_id, import_id) REFERENCES public.imported_subscription_revisions(id, tenant_id, import_id);


--
-- Name: imported_subscription_profiles imported_subscription_profiles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_profiles
    ADD CONSTRAINT imported_subscription_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.bot_profiles(tenant_id);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_import_id_settings_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_import_id_settings_sha256_fkey FOREIGN KEY (import_id, settings_sha256) REFERENCES public.remnawave_subscription_settings(import_id, settings_sha256);


--
-- Name: imported_subscription_revisions imported_subscription_revisions_import_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_revisions
    ADD CONSTRAINT imported_subscription_revisions_import_id_tenant_id_fkey FOREIGN KEY (import_id, tenant_id) REFERENCES public.remnawave_imports(id, tenant_id);


--
-- Name: imported_subscription_squad_services imported_subscription_squad_serv_tenant_id_source_squad_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_squad_services
    ADD CONSTRAINT imported_subscription_squad_serv_tenant_id_source_squad_id_fkey FOREIGN KEY (tenant_id, source_squad_id) REFERENCES public.bot_squads(tenant_id, source_uuid);


--
-- Name: imported_subscription_squad_services imported_subscription_squad_services_revision_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_squad_services
    ADD CONSTRAINT imported_subscription_squad_services_revision_id_tenant_id_fkey FOREIGN KEY (revision_id, tenant_id) REFERENCES public.imported_subscription_revisions(id, tenant_id);


--
-- Name: imported_subscription_squad_services imported_subscription_squad_services_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_subscription_squad_services
    ADD CONSTRAINT imported_subscription_squad_services_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id);


--
-- Name: imported_tls_certificates imported_tls_certificates_certificate_id_node_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_tls_certificates
    ADD CONSTRAINT imported_tls_certificates_certificate_id_node_id_tenant_id_fkey FOREIGN KEY (certificate_id, node_id, tenant_id) REFERENCES public.node_certificates(id, node_id, tenant_id) ON DELETE RESTRICT;


--
-- Name: imported_tls_certificates imported_tls_certificates_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_tls_certificates
    ADD CONSTRAINT imported_tls_certificates_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256);


--
-- Name: imported_tls_certificates imported_tls_certificates_import_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.imported_tls_certificates
    ADD CONSTRAINT imported_tls_certificates_import_id_tenant_id_fkey FOREIGN KEY (import_id, tenant_id) REFERENCES public.remnawave_imports(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: ingress_companions ingress_companions_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_companions
    ADD CONSTRAINT ingress_companions_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: ingress_provision_runs ingress_provision_runs_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_runs
    ADD CONSTRAINT ingress_provision_runs_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id);


--
-- Name: ingress_provision_tasks ingress_provision_tasks_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_tasks
    ADD CONSTRAINT ingress_provision_tasks_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id);


--
-- Name: ingress_provision_tasks ingress_provision_tasks_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingress_provision_tasks
    ADD CONSTRAINT ingress_provision_tasks_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.ingress_provision_runs(id);


--
-- Name: node_backup_reports node_backup_reports_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_backup_reports
    ADD CONSTRAINT node_backup_reports_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_certificates node_certificates_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_certificates node_certificates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_certificates
    ADD CONSTRAINT node_certificates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: node_client_traffic_cursors node_client_traffic_cursors_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_client_traffic_cursors
    ADD CONSTRAINT node_client_traffic_cursors_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE CASCADE;


--
-- Name: node_client_traffic_cursors node_client_traffic_cursors_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_client_traffic_cursors
    ADD CONSTRAINT node_client_traffic_cursors_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_core_update_policies node_core_update_policies_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_core_update_policies
    ADD CONSTRAINT node_core_update_policies_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_health node_health_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_health
    ADD CONSTRAINT node_health_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_ingress_policies node_ingress_policies_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_ingress_policies
    ADD CONSTRAINT node_ingress_policies_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_metric_samples node_metric_samples_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_metric_samples
    ADD CONSTRAINT node_metric_samples_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_reboot_jobs node_reboot_jobs_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_reboot_jobs
    ADD CONSTRAINT node_reboot_jobs_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_reboot_jobs node_reboot_jobs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_reboot_jobs
    ADD CONSTRAINT node_reboot_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: node_retirements node_retirements_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_retirements
    ADD CONSTRAINT node_retirements_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id);


--
-- Name: node_security_policies node_security_policies_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_security_policies
    ADD CONSTRAINT node_security_policies_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_security_reports node_security_reports_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_security_reports
    ADD CONSTRAINT node_security_reports_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_traffic_delivery node_traffic_delivery_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_traffic_delivery
    ADD CONSTRAINT node_traffic_delivery_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: node_xray_profile_bindings node_xray_profile_bindings_node_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profile_bindings
    ADD CONSTRAINT node_xray_profile_bindings_node_id_tenant_id_fkey FOREIGN KEY (node_id, tenant_id) REFERENCES public.node_xray_profiles(node_id, tenant_id) ON DELETE RESTRICT;


--
-- Name: node_xray_profile_bindings node_xray_profile_bindings_service_id_tenant_id_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profile_bindings
    ADD CONSTRAINT node_xray_profile_bindings_service_id_tenant_id_node_id_fkey FOREIGN KEY (service_id, tenant_id, node_id) REFERENCES public.vpn_services(id, tenant_id, node_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: node_xray_profiles node_xray_profiles_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256);


--
-- Name: node_xray_profiles node_xray_profiles_import_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_import_id_tenant_id_fkey FOREIGN KEY (import_id, tenant_id) REFERENCES public.remnawave_imports(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: node_xray_profiles node_xray_profiles_node_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_xray_profiles
    ADD CONSTRAINT node_xray_profiles_node_id_tenant_id_fkey FOREIGN KEY (node_id, tenant_id) REFERENCES public.nodes(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: nodes nodes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: pauk_remnawave_quota_schedules pauk_remnawave_quota_schedules_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pauk_remnawave_quota_schedules
    ADD CONSTRAINT pauk_remnawave_quota_schedules_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_client_continuous_quotas(client_id) ON DELETE CASCADE;


--
-- Name: protocol_ingress_entry_nodes protocol_ingress_entry_nodes_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_entry_nodes
    ADD CONSTRAINT protocol_ingress_entry_nodes_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: protocol_ingress_ports protocol_ingress_ports_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_ports
    ADD CONSTRAINT protocol_ingress_ports_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.vpn_services(id) ON DELETE CASCADE;


--
-- Name: protocol_ingress_reports protocol_ingress_reports_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_ingress_reports
    ADD CONSTRAINT protocol_ingress_reports_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.vpn_services(id) ON DELETE CASCADE;


--
-- Name: protocol_template_installations protocol_template_installations_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_template_installations
    ADD CONSTRAINT protocol_template_installations_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: protocol_template_installations protocol_template_installations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_template_installations
    ADD CONSTRAINT protocol_template_installations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: recovery_attempts recovery_attempts_deployment_exact_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_deployment_exact_fk FOREIGN KEY (deployment_id, node_id, proposed_generation) REFERENCES public.deployments(id, node_id, generation) ON DELETE RESTRICT;


--
-- Name: recovery_attempts recovery_attempts_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: recovery_attempts recovery_attempts_source_exact_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_source_exact_fk FOREIGN KEY (source_deployment_id, node_id, source_generation) REFERENCES public.deployments(id, node_id, generation) ON DELETE RESTRICT;


--
-- Name: recovery_attempts recovery_attempts_target_core_release_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_target_core_release_id_fkey FOREIGN KEY (target_core_release_id) REFERENCES public.core_releases(id);


--
-- Name: recovery_attempts recovery_attempts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_attempts
    ADD CONSTRAINT recovery_attempts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: remnawave_cutovers remnawave_cutovers_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_cutovers
    ADD CONSTRAINT remnawave_cutovers_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256);


--
-- Name: remnawave_cutovers remnawave_cutovers_import_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_cutovers
    ADD CONSTRAINT remnawave_cutovers_import_id_tenant_id_fkey FOREIGN KEY (import_id, tenant_id) REFERENCES public.remnawave_imports(id, tenant_id);


--
-- Name: remnawave_cutovers remnawave_cutovers_subscription_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_cutovers
    ADD CONSTRAINT remnawave_cutovers_subscription_revision_id_fkey FOREIGN KEY (subscription_revision_id) REFERENCES public.imported_subscription_revisions(id);


--
-- Name: remnawave_import_clients remnawave_import_clients_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_clients
    ADD CONSTRAINT remnawave_import_clients_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE RESTRICT;


--
-- Name: remnawave_import_clients remnawave_import_clients_import_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_clients
    ADD CONSTRAINT remnawave_import_clients_import_id_fkey FOREIGN KEY (import_id) REFERENCES public.remnawave_imports(id) ON DELETE RESTRICT;


--
-- Name: remnawave_import_heads remnawave_import_heads_import_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_heads
    ADD CONSTRAINT remnawave_import_heads_import_id_fkey FOREIGN KEY (import_id) REFERENCES public.remnawave_imports(id) ON DELETE CASCADE;


--
-- Name: remnawave_import_heads remnawave_import_heads_import_id_inventory_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_import_heads
    ADD CONSTRAINT remnawave_import_heads_import_id_inventory_sha256_fkey FOREIGN KEY (import_id, inventory_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: remnawave_imports remnawave_imports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_imports
    ADD CONSTRAINT remnawave_imports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: remnawave_inventory_revisions remnawave_inventory_revisions_import_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_inventory_revisions
    ADD CONSTRAINT remnawave_inventory_revisions_import_id_fkey FOREIGN KEY (import_id) REFERENCES public.remnawave_imports(id) ON DELETE CASCADE;


--
-- Name: remnawave_inventory_revisions remnawave_inventory_revisions_import_id_parent_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_inventory_revisions
    ADD CONSTRAINT remnawave_inventory_revisions_import_id_parent_sha256_fkey FOREIGN KEY (import_id, parent_sha256) REFERENCES public.remnawave_inventory_revisions(import_id, inventory_sha256) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: remnawave_subscription_settings remnawave_subscription_settings_import_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_subscription_settings
    ADD CONSTRAINT remnawave_subscription_settings_import_id_fkey FOREIGN KEY (import_id) REFERENCES public.remnawave_imports(id) ON DELETE RESTRICT;


--
-- Name: reseller_children reseller_children_child_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_children
    ADD CONSTRAINT reseller_children_child_tenant_id_fkey FOREIGN KEY (child_tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: reseller_children reseller_children_parent_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_children
    ADD CONSTRAINT reseller_children_parent_tenant_id_fkey FOREIGN KEY (parent_tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT;


--
-- Name: rollout_plans rollout_plans_deployment_exact_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_deployment_exact_fk FOREIGN KEY (deployment_id, node_id, proposed_generation) REFERENCES public.deployments(id, node_id, generation) ON DELETE RESTRICT;


--
-- Name: rollout_plans rollout_plans_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: rollout_plans rollout_plans_target_core_release_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_target_core_release_id_fkey FOREIGN KEY (target_core_release_id) REFERENCES public.core_releases(id);


--
-- Name: rollout_plans rollout_plans_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_plans
    ADD CONSTRAINT rollout_plans_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: service_ingress_policies service_ingress_policies_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_ingress_policies
    ADD CONSTRAINT service_ingress_policies_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.vpn_services(id) ON DELETE CASCADE;


--
-- Name: tenant_api_tokens tenant_api_tokens_issued_by_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_api_tokens
    ADD CONSTRAINT tenant_api_tokens_issued_by_token_id_fkey FOREIGN KEY (issued_by_token_id) REFERENCES public.tenant_api_tokens(id) ON DELETE CASCADE;


--
-- Name: tenant_api_tokens tenant_api_tokens_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_api_tokens
    ADD CONSTRAINT tenant_api_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_auto_profile_publications tenant_auto_profile_publications_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_publications
    ADD CONSTRAINT tenant_auto_profile_publications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_auto_profile_refresh_runs tenant_auto_profile_refresh_runs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_refresh_runs
    ADD CONSTRAINT tenant_auto_profile_refresh_runs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_auto_profile_refresh_schedules tenant_auto_profile_refresh_schedules_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profile_refresh_schedules
    ADD CONSTRAINT tenant_auto_profile_refresh_schedules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_auto_profiles tenant_auto_profiles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_auto_profiles
    ADD CONSTRAINT tenant_auto_profiles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_branding tenant_branding_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_branding
    ADD CONSTRAINT tenant_branding_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_resource_limits tenant_resource_limits_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_resource_limits
    ADD CONSTRAINT tenant_resource_limits_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_access_plan_services vpn_access_plan_services_plan_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plan_services
    ADD CONSTRAINT vpn_access_plan_services_plan_tenant_fk FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_access_plan_services vpn_access_plan_services_service_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plan_services
    ADD CONSTRAINT vpn_access_plan_services_service_tenant_fk FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_access_plans vpn_access_plans_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_access_plans
    ADD CONSTRAINT vpn_access_plans_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_cascades vpn_cascades_entry_service_id_tenant_id_entry_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_entry_service_id_tenant_id_entry_node_id_fkey FOREIGN KEY (entry_service_id, tenant_id, entry_node_id) REFERENCES public.vpn_services(id, tenant_id, node_id);


--
-- Name: vpn_cascades vpn_cascades_exit_service_id_tenant_id_exit_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_exit_service_id_tenant_id_exit_node_id_fkey FOREIGN KEY (exit_service_id, tenant_id, exit_node_id) REFERENCES public.vpn_services(id, tenant_id, node_id);


--
-- Name: vpn_cascades vpn_cascades_plan_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_plan_id_tenant_id_fkey FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_cascades vpn_cascades_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_cascades
    ADD CONSTRAINT vpn_cascades_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_client_access_plans vpn_client_access_plans_client_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_access_plans
    ADD CONSTRAINT vpn_client_access_plans_client_tenant_fk FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_access_plans vpn_client_access_plans_plan_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_access_plans
    ADD CONSTRAINT vpn_client_access_plans_plan_tenant_fk FOREIGN KEY (plan_id, tenant_id) REFERENCES public.vpn_access_plans(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_continuous_quotas vpn_client_continuous_quotas_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_continuous_quotas
    ADD CONSTRAINT vpn_client_continuous_quotas_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE CASCADE;


--
-- Name: vpn_client_limits vpn_client_limits_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_limits
    ADD CONSTRAINT vpn_client_limits_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE CASCADE;


--
-- Name: vpn_client_openvpn_certificates vpn_client_openvpn_certificates_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_openvpn_certificates
    ADD CONSTRAINT vpn_client_openvpn_certificates_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_openvpn_certificates vpn_client_openvpn_certificates_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_openvpn_certificates
    ADD CONSTRAINT vpn_client_openvpn_certificates_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_pptp vpn_client_pptp_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_pptp
    ADD CONSTRAINT vpn_client_pptp_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_pptp vpn_client_pptp_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_pptp
    ADD CONSTRAINT vpn_client_pptp_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_services vpn_client_services_client_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_services
    ADD CONSTRAINT vpn_client_services_client_tenant_fk FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_services vpn_client_services_service_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_services
    ADD CONSTRAINT vpn_client_services_service_tenant_fk FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_shadowsocks_keys vpn_client_shadowsocks_keys_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_shadowsocks_keys
    ADD CONSTRAINT vpn_client_shadowsocks_keys_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_subscriptions vpn_client_subscriptions_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_subscriptions
    ADD CONSTRAINT vpn_client_subscriptions_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE CASCADE;


--
-- Name: vpn_client_subscriptions vpn_client_subscriptions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_subscriptions
    ADD CONSTRAINT vpn_client_subscriptions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_client_usage_monthly vpn_client_usage_monthly_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_usage_monthly
    ADD CONSTRAINT vpn_client_usage_monthly_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.vpn_clients(id) ON DELETE CASCADE;


--
-- Name: vpn_client_wireguard vpn_client_wireguard_client_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_wireguard
    ADD CONSTRAINT vpn_client_wireguard_client_id_tenant_id_fkey FOREIGN KEY (client_id, tenant_id) REFERENCES public.vpn_clients(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_client_wireguard vpn_client_wireguard_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_client_wireguard
    ADD CONSTRAINT vpn_client_wireguard_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_clients vpn_clients_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_clients
    ADD CONSTRAINT vpn_clients_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_service_amneziawg vpn_service_amneziawg_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_amneziawg
    ADD CONSTRAINT vpn_service_amneziawg_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_service_openvpn vpn_service_openvpn_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_openvpn
    ADD CONSTRAINT vpn_service_openvpn_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_node_id_fkey FOREIGN KEY (node_id) REFERENCES public.nodes(id) ON DELETE CASCADE;


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_request_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_request_key_fkey FOREIGN KEY (request_key) REFERENCES public.protocol_template_installations(request_key) ON DELETE CASCADE;


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.vpn_services(id) ON DELETE CASCADE;


--
-- Name: vpn_service_protocol_templates vpn_service_protocol_templates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_protocol_templates
    ADD CONSTRAINT vpn_service_protocol_templates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: vpn_service_reality vpn_service_reality_service_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_reality
    ADD CONSTRAINT vpn_service_reality_service_tenant_fk FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_service_shadowsocks vpn_service_shadowsocks_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_shadowsocks
    ADD CONSTRAINT vpn_service_shadowsocks_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_service_tls vpn_service_tls_certificate_id_tenant_id_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_tls
    ADD CONSTRAINT vpn_service_tls_certificate_id_tenant_id_node_id_fkey FOREIGN KEY (certificate_id, tenant_id, node_id) REFERENCES public.node_certificates(id, tenant_id, node_id) ON DELETE RESTRICT;


--
-- Name: vpn_service_tls vpn_service_tls_service_id_tenant_id_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_tls
    ADD CONSTRAINT vpn_service_tls_service_id_tenant_id_node_id_fkey FOREIGN KEY (service_id, tenant_id, node_id) REFERENCES public.vpn_services(id, tenant_id, node_id) ON DELETE CASCADE;


--
-- Name: vpn_service_wireguard vpn_service_wireguard_service_id_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_service_wireguard
    ADD CONSTRAINT vpn_service_wireguard_service_id_tenant_id_fkey FOREIGN KEY (service_id, tenant_id) REFERENCES public.vpn_services(id, tenant_id) ON DELETE CASCADE;


--
-- Name: vpn_services vpn_services_node_tenant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vpn_services
    ADD CONSTRAINT vpn_services_node_tenant_fk FOREIGN KEY (node_id, tenant_id) REFERENCES public.nodes(id, tenant_id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.webhook_endpoints(id) ON DELETE CASCADE;


--
-- Name: webhook_endpoints webhook_endpoints_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

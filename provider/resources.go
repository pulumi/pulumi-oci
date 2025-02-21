// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"fmt"
	"path/filepath"
	"strings"

	// embed is used to store bridge-metadata.json in the compiled binary
	_ "embed"

	ociShim "github.com/oracle/terraform-provider-oci/shim"

	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge"
	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge/tokens"
	shimv2 "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim/sdk-v2"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"

	"github.com/pulumi/pulumi-oci/provider/v2/pkg/version"
)

// all of the token components used below.
const (
	// This variable controls the default name of the package in the package
	// registries for nodejs and python:
	mainPkg = "oci"
	// modules:
	admMod                          = "Adm"                    // ADM
	aiAnomalyDetectionMod           = "AiAnomalyDetection"     // AI Anomaly Detection
	aiDocumentMod                   = "AiDocument"             // AI Document
	aiLanguageMod                   = "AiLanguage"             // AI Language
	aiVisionMod                     = "AiVision"               // AI Vision
	analyticsMod                    = "Analytics"              // Analytics
	announcementsServiceMod         = "AnnouncementsService"   // Announcements Service
	apiGatewayMod                   = "ApiGateway"             // API Gateway
	apmConfigMod                    = "ApmConfig"              // APM Config
	apmMod                          = "Apm"                    // APM
	apmSyntheticsMod                = "ApmSynthetics"          // APM Synthetics
	apmTracesMod                    = "ApmTraces"              // APM Traces
	appMgmtControlMod               = "AppMgmtControl"         // AppMgmt Control
	artifactsMod                    = "Artifacts"              // Artifacts
	auditMod                        = "Audit"                  // Audit
	autoscalingMod                  = "Autoscaling"            // Autoscaling
	bastionMod                      = "Bastion"                // Autoscaling
	bigDataServiceMod               = "BigDataService"         // Big Data Service
	blockchainMod                   = "Blockchain"             // Blockchain
	budgetMod                       = "Budget"                 // Budget
	capacityManagementMod           = "CapacityManagement"     // Capacity Management
	certificatesManagementMod       = "CertificatesManagement" // Certificates Management
	cloudBridgeMod                  = "CloudBridge"            // Cloud Bridge
	cloudGuardMod                   = "CloudGuard"             // Cloud Guard
	cloudMigrationsMod              = "CloudMigrations"        // Cloud Migrations
	clusterPlacementGroups          = "ClusterPlacementGroups" // Cluster Placement Groups
	computeCloudMod                 = "ComputeCloud"           // Compute Cloud
	computeInstanceAgent            = "ComputeInstanceAgent"   // Compute Instance Agent
	containerEngineMod              = "ContainerEngine"        // Container Engine
	containerInstancesMod           = "ContainerInstances"     // Container Instances
	coreMod                         = "Core"                   // Core
	dataCatalogMod                  = "DataCatalog"            // Data Catalog
	dataFlowMod                     = "DataFlow"               // Data Flow
	dataIntegrationMod              = "DataIntegration"        // Data Integration
	dataLabellingServiceMod         = "DataLabellingService"   // Data Labelling Service
	dataSafeMod                     = "DataSafe"               // Data Safe
	dataScienceMod                  = "DataScience"            // Data Science
	databaseManagementMod           = "DatabaseManagement"     // Database Management
	databaseMigrationMod            = "DatabaseMigration"      // Database Migration
	databaseMod                     = "Database"               // Database
	databaseToolsMod                = "DatabaseTools"          // Database Tools
	demandSignalMod                 = "DemandSignal"           // Demand Signal
	devopsMod                       = "DevOps"                 // DevOps
	disasterRecoveryMod             = "DisasterRecovery"       // Disaster Recovery
	dnsMod                          = "Dns"                    // DNS
	emWarehouseMod                  = "EmWarehouse"            // EM Warehouse
	emailMod                        = "Email"                  // Email
	eventsMod                       = "Events"                 // Events
	fileStorageMod                  = "FileStorage"            // File Storage
	fleetAppsManagementMod          = "FleetAppsManagement"
	fleetSoftwareUpdateMod          = "FleetSoftwareUpdate"          // Fleet Software Update
	functionsMod                    = "Functions"                    // Functions
	fusionAppsMod                   = "FusionApps"                   // Fusion Apps
	genericArtifactsContentMod      = "GenericArtifactsContent"      // Generic Artifacts Content
	goldenGateMod                   = "GoldenGate"                   // Golden Gate
	healthChecksMod                 = "HealthChecks"                 // Health Checks
	identityDataPlaneMod            = "IdentityDataPlane"            // Identity Data Plane
	identityMod                     = "Identity"                     // Identity
	integrationMod                  = "Integration"                  // Integration
	jmsMod                          = "Jms"                          // Jms
	kmsMod                          = "Kms"                          // Kms
	licenseManagerMod               = "LicenseManager"               // License Manager
	limitsMod                       = "Limits"                       // Limits
	loadBalancerMod                 = "LoadBalancer"                 // Load Balancer
	logAnalyticsMod                 = "LogAnalytics"                 // Log Analytics
	loggingMod                      = "Logging"                      // Logging
	managementAgentMod              = "ManagementAgent"              // Management Agent
	managementDashboardMod          = "ManagementDashboard"          // Management Dashboard
	marketplaceMod                  = "Marketplace"                  // Marketplace
	mediaServicesMod                = "MediaServices"                // Media Services
	meteringComputationMod          = "MeteringComputation"          // Metering Computation
	monitoringMod                   = "Monitoring"                   // Monitoring
	mysqlMod                        = "Mysql"                        // Mysql
	networkFirewallMod              = "NetworkFirewall"              // Network Firewall
	networkLoadBalancerMod          = "NetworkLoadBalancer"          // Network Load Balancer
	nosqlMod                        = "Nosql"                        // Nosql
	objectStorageMod                = "ObjectStorage"                // Object Storage
	oceMod                          = "Oce"                          // OCE
	ocvpMod                         = "Ocvp"                         // OCVP
	odaMod                          = "Oda"                          // Oda
	oneSubscriptionMod              = "OneSubsription"               // One Subscription
	onsMod                          = "Ons"                          // Ons
	opaMod                          = "Opa"                          // OPA (Oracle Policy Agent)
	opensearchMod                   = "Opensearch"                   // Opensearch
	operatorAccessControlMod        = "OperatorAccessControl"        // Operator Access Control
	opsiMod                         = "Opsi"                         // Opsi
	optimizerMod                    = "Optimizer"                    // Optimizer
	osManagementHubMod              = "OsManagementHub"              // Os Management Hub
	osManagementMod                 = "OsManagement"                 // Os Management
	ospGatewayMod                   = "OspGateway"                   // Osp Gateway
	osubBillingScheduleMod          = "OsubBillingSchedule"          // Osub Billing Schedule
	osubOrganizationSubscriptionMod = "OsubOrganizationSubscription" // Osub Organization Subscription
	osubSubscriptionMod             = "OsubSubscription"             // Osub Subscription
	osubUsageMod                    = "OsubUsage"                    // Osub Usage
	psqlMod                         = "Psql"                         // PSQL
	queueMod                        = "Queue"                        // Queue
	recoveryMod                     = "RecoveryMod"                  // Recovery
	redisMod                        = "Redis"                        // Redis
	resourceManagerMod              = "ResourceManager"              // Resource Manager
	schMod                          = "Sch"                          // Sch
	secretsMod                      = "Secrets"                      // Secrets
	securityAttributeMod            = "SecurityAttribute"
	serviceCatalogMod               = "ServiceCatalog"        // Service Catalog
	serviceManagerProxyMod          = "ServiceManagerProxy"   // Service Manager Proxy
	serviceMeshMod                  = "ServiceMesh"           // Service Mesh
	stackMonitoringMod              = "StackMonitoring"       // Stack Monitoring
	streamingMod                    = "Streaming"             // Streaming
	usageProxyMod                   = "UsageProxy"            // Usage Proxy
	vaultMod                        = "Vault"                 // Vault
	vbsMod                          = "Vbs"                   // VBS
	visualBuilderMod                = "VisualBuilder"         // Visual Builder
	vnMonitoringMod                 = "VnMonitoring"          // Vn Monitoring
	vulnerabilityScanningMod        = "VulnerabilityScanning" // VulnerabilityScanning
	waaMod                          = "Waa"
	waasMod                         = "Waas"
	wafMod                          = "Waf"
	zprMod                          = "Zpr"
)

// A mapping between the terraform prefix and the pulumi module name.
// This mapping is used by x.TokensKnownModules to compute module names.
var mappedMods = map[string]string{
	"adm":                            admMod,
	"ai_anomaly_detection":           aiAnomalyDetectionMod,
	"ai_document":                    aiDocumentMod,
	"ai_language":                    aiLanguageMod,
	"ai_vision":                      aiVisionMod,
	"analytics":                      analyticsMod,
	"announcements_service":          announcementsServiceMod,
	"apigateway":                     apiGatewayMod,
	"apm":                            apmMod,
	"apm_config":                     apmConfigMod,
	"apm_synthetics":                 apmSyntheticsMod,
	"apm_traces":                     apmTracesMod,
	"appmgmt_control":                appMgmtControlMod,
	"artifacts":                      artifactsMod,
	"audit":                          auditMod,
	"autoscaling":                    autoscalingMod,
	"bastion":                        bastionMod,
	"bds":                            bigDataServiceMod,
	"blockchain":                     blockchainMod,
	"budget":                         budgetMod,
	"capacity_management":            capacityManagementMod,
	"certificates_management":        certificatesManagementMod,
	"cloud_bridge":                   cloudBridgeMod,
	"cloud_guard":                    cloudGuardMod,
	"cloud_migrations":               cloudMigrationsMod,
	"cluster_placement_groups":       clusterPlacementGroups,
	"compute_cloud":                  computeCloudMod,
	"computeinstanceagent":           computeInstanceAgent,
	"container_instances":            containerInstancesMod,
	"containerengine":                containerEngineMod,
	"core":                           coreMod,
	"data_labeling_service":          dataLabellingServiceMod,
	"data_labelling_service":         dataLabellingServiceMod,
	"data_safe":                      dataSafeMod,
	"database":                       databaseMod,
	"database_management":            databaseManagementMod,
	"database_migration":             databaseMigrationMod,
	"database_tools":                 databaseToolsMod,
	"datacatalog":                    dataCatalogMod,
	"dataflow":                       dataFlowMod,
	"dataintegration":                dataIntegrationMod,
	"datascience":                    dataScienceMod,
	"delegate_access_control":        "DelegateAccessControl",
	"demand_signal":                  demandSignalMod,
	"desktops":                       "Desktops",
	"devops":                         devopsMod,
	"disaster_recovery":              disasterRecoveryMod,
	"dns":                            dnsMod,
	"em_warehouse":                   emWarehouseMod,
	"email":                          emailMod,
	"events":                         eventsMod,
	"file_storage":                   fileStorageMod,
	"fleet_apps_management":          fleetAppsManagementMod,
	"fleet_software_update":          fleetSoftwareUpdateMod,
	"functions":                      functionsMod,
	"fusion_apps":                    fusionAppsMod,
	"generative_ai":                  "GenerativeAi",
	"generic_artifacts_content":      genericArtifactsContentMod,
	"globally_distributed_database":  "GloballyDistributedDatabase",
	"golden_gate":                    goldenGateMod,
	"health_checks":                  healthChecksMod,
	"identity":                       identityMod,
	"identity_data_plane":            identityDataPlaneMod,
	"integration":                    integrationMod,
	"jms":                            jmsMod,
	"kms":                            kmsMod,
	"license_manager":                licenseManagerMod,
	"limits":                         limitsMod,
	"load_balancer":                  loadBalancerMod,
	"log_analytics":                  logAnalyticsMod,
	"logging":                        loggingMod,
	"management_agent":               managementAgentMod,
	"management_dashboard":           managementDashboardMod,
	"marketplace":                    marketplaceMod,
	"media_services":                 mediaServicesMod,
	"metering_computation":           meteringComputationMod,
	"monitoring":                     monitoringMod,
	"mysql":                          mysqlMod,
	"network_firewall":               networkFirewallMod,
	"network_load_balancer":          networkLoadBalancerMod,
	"nosql":                          nosqlMod,
	"objectstorage":                  objectStorageMod,
	"oce":                            oceMod,
	"ocvp":                           ocvpMod,
	"oda":                            odaMod,
	"onesubscription":                oneSubscriptionMod,
	"ons":                            onsMod,
	"opa":                            opaMod,
	"opensearch":                     opensearchMod,
	"operator_access_control":        operatorAccessControlMod,
	"opsi":                           opsiMod,
	"optimizer":                      optimizerMod,
	"os_management_hub":              osManagementHubMod,
	"osmanagement":                   osManagementMod,
	"osp_gateway":                    ospGatewayMod,
	"osub_billing_schedule":          osubBillingScheduleMod,
	"osub_organization_subscription": osubOrganizationSubscriptionMod,
	"osub_subscription":              osubSubscriptionMod,
	"osub_usage":                     osubUsageMod,
	"psql":                           psqlMod,
	"queue":                          queueMod,
	"recovery":                       recoveryMod,
	"redis":                          redisMod,
	"resourcemanager":                resourceManagerMod,
	"resource_scheduler":             "ResourceScheduler",
	"security_attribute":             securityAttributeMod,
	"sch":                            schMod,
	"secrets":                        secretsMod,
	"service_catalog":                serviceCatalogMod,
	"service_manager_proxy":          serviceManagerProxyMod,
	"service_mesh":                   serviceMeshMod,
	"stack_monitoring":               stackMonitoringMod,
	"streaming":                      streamingMod,
	"tenantmanagercontrolplane":      "Tenantmanagercontrolplane",
	"usage_proxy":                    usageProxyMod,
	"vault":                          vaultMod,
	"vbs":                            vbsMod,
	"visual_builder":                 visualBuilderMod,
	"vn_monitoring":                  vnMonitoringMod,
	"vulnerability_scanning":         vulnerabilityScanningMod,
	"waa":                            waaMod,
	"waas":                           waasMod,
	"waf":                            wafMod,
	"zpr":                            zprMod,
}

// Provider returns additional overlaid schema and metadata associated with the provider
//
// The datasource map has long lines
//
//nolint:lll
func Provider() tfbridge.ProviderInfo {
	// Instantiate the Terraform provider
	p := shimv2.NewProvider(ociShim.NewProvider())

	// Create a Pulumi provider mapping
	prov := tfbridge.ProviderInfo{
		P:    p,
		Name: "oci",
		// DisplayName is a way to be able to change the casing of the provider
		// name when being displayed on the Pulumi registry
		DisplayName: "Oracle Cloud Infrastructure",
		// The default publisher for all packages is Pulumi.
		// Change this to your personal name (or a company name) that you
		// would like to be shown in the Pulumi Registry if this package is published
		// there.
		Publisher: "Pulumi",
		// LogoURL is optional but useful to help identify your package in the Pulumi Registry
		// if this package is published there.
		//
		// You may host a logo on a domain you control or add an SVG logo for your package
		// in your repository and use the raw content URL for that file as your logo URL.
		LogoURL:     "",
		Description: "A Pulumi package for creating and managing Oracle Cloud Infrastructure resources.",
		Keywords:    []string{"pulumi", "oci", "oracle", "category/cloud"},
		License:     "Apache-2.0",
		Homepage:    "https://www.pulumi.com",
		Repository:  "https://github.com/pulumi/pulumi-oci",
		Config:      map[string]*tfbridge.SchemaInfo{},
		GitHubOrg:   "oracle",
		Version:     version.Version,
		DocRules: &tfbridge.DocRuleInfo{
			AlternativeNames: func(info tfbridge.DocsPathInfo) []string {
				if rest, ok := strings.CutPrefix(info.TfToken, "oci_datascience"); ok {
					return []string{"datascience_data_science" + rest + ".html.markdown"}
				}
				return nil
			},
		},

		IgnoreMappings: []string{
			"oci_database_migration",
			"oci_load_balancer",
			"oci_load_balancer_backendset",
			"oci_devops_repository_mirrorrecord",
			"oci_load_balancer_backendsets",
			"oci_load_balancers",
			"oci_database_migration_jobs",
			"oci_database_migration_job",
			"oci_data_safe_discovery_jobs",
		},
		Resources: map[string]*tfbridge.ResourceInfo{
			"oci_apigateway_certificate": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"certificate": {CSharpName: "CertificateDetails"},
				},
			},

			"oci_apm_synthetics_monitor": {Tok: tfbridge.MakeResource(mainPkg, apmSyntheticsMod, "Config")},

			"oci_budget_alert_rule": {Tok: tfbridge.MakeResource(mainPkg, budgetMod, "Rule")},

			"oci_cloud_guard_data_source": {
				Tok: tfbridge.MakeResource(mainPkg, cloudGuardMod, "CloudGuardDataSource"),
			},

			"oci_container_instances_container_instance": {
				Tok: tfbridge.MakeResource(mainPkg, containerEngineMod, "ContainerInstance"),
			},

			"oci_core_app_catalog_listing_resource_version_agreement": {
				Tok: tfbridge.MakeResource(mainPkg, coreMod, "AppCatalogListingResourceVersionAgreement"),
			},

			"oci_core_listing_resource_version_agreement": {
				Docs: &tfbridge.DocInfo{Source: "core_app_catalog_listing_resource_version_agreement.html.markdown"},
			},

			"oci_data_safe_discovery_job": {Tok: tfbridge.MakeResource(mainPkg, dataSafeMod, "DiscoveryMod")},

			// Typo: masking -> Masing
			"oci_data_safe_library_masking_format": {Tok: tfbridge.MakeResource(mainPkg, dataSafeMod, "LibraryMasingFormat")},

			"oci_database_database": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"database": {
						CSharpName: "DatabaseName",
					},
				},
			},

			"oci_database_pluggable_database_pluggabledatabasemanagements_management": {
				Tok: tfbridge.MakeResource(mainPkg, databaseMod, "PluggableDatabaseManagementsManagement"),
			},

			"oci_datascience_pipeline": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"step_artifact": {
						Elem: &tfbridge.SchemaInfo{
							Fields: map[string]*tfbridge.SchemaInfo{
								"pipeline_step_artifact": {
									CSharpName: "StepArtifact",
								},
							},
						},
					},
				},
			},

			"oci_database_migration_job": {Tok: tfbridge.MakeResource(mainPkg, databaseMigrationMod, "Job")},

			"oci_database_vm_cluster_add_virtual_machine": {
				Tok: tfbridge.MakeResource(mainPkg, databaseMod, "VmClusterAddVirtualNetwork"),
			},

			"oci_database_externalcontainerdatabases_stack_monitoring": {
				Tok: tfbridge.MakeResource(mainPkg, databaseMod, "ExternalContainerDatabasesStackMonitoring"),
			},
			"oci_database_externalnoncontainerdatabases_stack_monitoring": {
				Tok: tfbridge.MakeResource(mainPkg, databaseMod, "ExternalNonContainerDatabasesStackMonitoring"),
			},
			"oci_database_externalpluggabledatabases_stack_monitoring": {
				Tok: tfbridge.MakeResource(mainPkg, databaseMod, "ExternalPluggableDatabasesStackMonitoring"),
			},

			"oci_load_balancer_hostname": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"hostname": {
						CSharpName: "VirtualHostname",
					},
				},
			},
			"oci_log_analytics_namespace": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"namespace": {
						CSharpName: "NamespaceName",
					},
				},
			},

			"oci_identity_data_plane_generate_scoped_access_token": {
				Tok: tfbridge.MakeResource(mainPkg, identityDataPlaneMod, "GeneratedScopedAccessToken"),
			},

			"oci_kms_vault_replication": {Tok: tfbridge.MakeResource(mainPkg, kmsMod, "VaultVerification")},

			"oci_objectstorage_object": {Tok: tfbridge.MakeResource(mainPkg, objectStorageMod, "StorageObject")},

			"oci_opensearch_opensearch_cluster": {Tok: tfbridge.MakeResource(mainPkg, opensearchMod, "Cluster")},

			"oci_service_catalog_service_catalog_association": {
				Tok: tfbridge.MakeResource(mainPkg, serviceCatalogMod, "CatalogAssociation"),
			},

			"oci_sch_service_connector": {Tok: tfbridge.MakeResource(mainPkg, schMod, "Connector")},

			"oci_service_catalog_service_catalog": {Tok: tfbridge.MakeResource(mainPkg, serviceCatalogMod, "Catalog")},

			"oci_waa_web_app_acceleration":        {Tok: tfbridge.MakeResource(mainPkg, waaMod, "AppAcceleration")},
			"oci_waa_web_app_acceleration_policy": {Tok: tfbridge.MakeResource(mainPkg, waaMod, "AppAccelerationPolicy")},

			"oci_waas_waas_policy": {Tok: tfbridge.MakeResource(mainPkg, waasMod, "Policy")},

			"oci_waf_web_app_firewall":        {Tok: tfbridge.MakeResource(mainPkg, wafMod, "AppFirewall")},
			"oci_waf_web_app_firewall_policy": {Tok: tfbridge.MakeResource(mainPkg, wafMod, "AppFirewallPolicy")},

			"oci_oce_oce_instance": {Tok: tfbridge.MakeResource(mainPkg, oceMod, "Instance")},

			"oci_osp_gateway_subscription": {
				Fields: map[string]*tfbridge.SchemaInfo{
					"subscription": {
						CSharpName: "SubscriptionDetails",
					},
				},
			},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			"oci_adm_knowledge_base":                   {Tok: tfbridge.MakeDataSource(mainPkg, admMod, "getKnowledgebase")},
			"oci_adm_knowledge_bases":                  {Tok: tfbridge.MakeDataSource(mainPkg, admMod, "getKnowledgebases")},
			"oci_ai_anomaly_detection_data_asset":      {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionDataAsset")},
			"oci_ai_anomaly_detection_data_assets":     {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionDataAssets")},
			"oci_ai_anomaly_detection_model":           {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionModel")},
			"oci_ai_anomaly_detection_models":          {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionModels")},
			"oci_ai_anomaly_detection_project":         {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionProject")},
			"oci_ai_anomaly_detection_projects":        {Tok: tfbridge.MakeDataSource(mainPkg, aiAnomalyDetectionMod, "getDetectionProjects")},
			"oci_apm_synthetics_public_vantage_point":  {Tok: tfbridge.MakeDataSource(mainPkg, apmSyntheticsMod, "getVantagePoint")},
			"oci_apm_synthetics_public_vantage_points": {Tok: tfbridge.MakeDataSource(mainPkg, apmSyntheticsMod, "getVantagePoints")},
			"oci_artifacts_container_image_signatures": {Tok: tfbridge.MakeDataSource(mainPkg, artifactsMod, "getContainerSignatures")},

			"oci_certificates_management_association":                    {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getAssociation")},
			"oci_certificates_management_associations":                   {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getAssociations")},
			"oci_certificates_management_ca_bundle":                      {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCaBundle")},
			"oci_certificates_management_ca_bundles":                     {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCaBundles")},
			"oci_certificates_management_certificate":                    {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificate")},
			"oci_certificates_management_certificate_authorities":        {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateAuthorities")},
			"oci_certificates_management_certificate_authority":          {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateAuthority")},
			"oci_certificates_management_certificate_authority_version":  {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateAuthorityVersion")},
			"oci_certificates_management_certificate_authority_versions": {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateAuthorityVersions")},
			"oci_certificates_management_certificate_version":            {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateVersion")},
			"oci_certificates_management_certificate_versions":           {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificateVersions")},
			"oci_certificates_management_certificates":                   {Tok: tfbridge.MakeDataSource(mainPkg, certificatesManagementMod, "getCertificates")},

			"oci_cloud_bridge_agent":               {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAgent")},
			"oci_cloud_bridge_agent_dependencies":  {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAgentDependencies")},
			"oci_cloud_bridge_agent_dependency":    {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAgentDependency")},
			"oci_cloud_bridge_agent_plugin":        {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAgentPlugin")},
			"oci_cloud_bridge_agents":              {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAgents")},
			"oci_cloud_bridge_appliance_image":     {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getApplianceImage")},
			"oci_cloud_bridge_appliance_images":    {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getApplianceImages")},
			"oci_cloud_bridge_asset":               {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAsset")},
			"oci_cloud_bridge_asset_source":        {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAssetSource")},
			"oci_cloud_bridge_asset_sources":       {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAssetSources")},
			"oci_cloud_bridge_assets":              {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getAssets")},
			"oci_cloud_bridge_discovery_schedule":  {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getDiscoverySchedule")},
			"oci_cloud_bridge_discovery_schedules": {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getDiscoverySchedules")},
			"oci_cloud_bridge_environment":         {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getEnvironment")},
			"oci_cloud_bridge_environments":        {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getEnvironments")},
			"oci_cloud_bridge_inventories":         {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getInventories")},
			"oci_cloud_bridge_inventory":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudBridgeMod, "getInventory")},

			"oci_cloud_guard_cloud_guard_configuration": {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getCloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":            {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataMaskRule")},
			"oci_cloud_guard_data_mask_rules":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataMaskRules")},
			"oci_cloud_guard_data_source":               {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataSource")},
			"oci_cloud_guard_data_source_event":         {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataSourceEvent")},
			"oci_cloud_guard_data_source_events":        {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataSourceEvents")},
			"oci_cloud_guard_data_sources":              {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDataSources")},
			"oci_cloud_guard_problem_entities":          {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getProblemEntities")},
			"oci_cloud_guard_problem_entity":            {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getProblemEntity")},
			"oci_cloud_guard_detector_recipe":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDetectorRecipe")},
			"oci_cloud_guard_detector_recipes":          {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getDetectorRecipes")},
			"oci_cloud_guard_managed_list":              {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getManagedList")},
			"oci_cloud_guard_managed_lists":             {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getManagedLists")},
			"oci_cloud_guard_responder_recipe":          {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getResponderRecipe")},
			"oci_cloud_guard_responder_recipes":         {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getResponderRecipes")},
			"oci_cloud_guard_target":                    {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getGuardTarget")},
			"oci_cloud_guard_targets":                   {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getGuardTargets")},
			"oci_cloud_guard_security_policies":         {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityPolicies")},
			"oci_cloud_guard_security_policy":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityPolicy")},
			"oci_cloud_guard_security_recipe":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityRecipe")},
			"oci_cloud_guard_security_recipes":          {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityRecipes")},
			"oci_cloud_guard_security_zone":             {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityZone")},
			"oci_cloud_guard_security_zones":            {Tok: tfbridge.MakeDataSource(mainPkg, cloudGuardMod, "getSecurityZones")},

			"oci_cloud_migrations_migration":                       {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigration")},
			"oci_cloud_migrations_migration_asset":                 {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationAsset")},
			"oci_cloud_migrations_migration_assets":                {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationAssets")},
			"oci_cloud_migrations_migration_plan":                  {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationPlan")},
			"oci_cloud_migrations_migration_plan_available_shape":  {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationPlanAvailableShape")},
			"oci_cloud_migrations_migration_plan_available_shapes": {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationPlanAvailableShapes")},
			"oci_cloud_migrations_migration_plans":                 {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrationPlans")},
			"oci_cloud_migrations_migrations":                      {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getMigrations")},
			"oci_cloud_migrations_replication_schedule":            {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getReplicationSchedule")},
			"oci_cloud_migrations_replication_schedules":           {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getReplicationSchedules")},
			"oci_cloud_migrations_target_asset":                    {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getTargetAsset")},
			"oci_cloud_migrations_target_assets":                   {Tok: tfbridge.MakeDataSource(mainPkg, cloudMigrationsMod, "getTargetAssets")},

			"oci_computeinstanceagent_instance_agent_plugin":      {Tok: tfbridge.MakeDataSource(mainPkg, computeInstanceAgent, "getInstanceAgentPlugin")},
			"oci_computeinstanceagent_instance_agent_plugins":     {Tok: tfbridge.MakeDataSource(mainPkg, computeInstanceAgent, "getInstanceAgentPlugins")},
			"oci_computeinstanceagent_instance_available_plugins": {Tok: tfbridge.MakeDataSource(mainPkg, computeInstanceAgent, "getInstanceAvailablePlugin")},

			"oci_containerengine_cluster_kube_config": {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getClusterKubeConfig")},
			"oci_containerengine_cluster_option":      {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getClusterOption")},
			"oci_containerengine_clusters":            {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getClusters")},
			"oci_containerengine_migrate_to_native_vcn_status": {
				Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getMigrateToNativeVcnStatus"),
			},
			"oci_containerengine_node_pool":                {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getNodePool")},
			"oci_containerengine_node_pool_option":         {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getNodePoolOption")},
			"oci_containerengine_node_pools":               {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getNodePools")},
			"oci_containerengine_work_request_errors":      {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getWorkRequestErrors")},
			"oci_containerengine_work_request_log_entries": {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getWorkRequestLogEntries")},
			"oci_containerengine_work_requests":            {Tok: tfbridge.MakeDataSource(mainPkg, containerEngineMod, "getWorkRequests")},

			"oci_container_instances_container_instance":        {Tok: tfbridge.MakeDataSource(mainPkg, containerInstancesMod, "getContainerInstance")},
			"oci_container_instances_container_instance_shape":  {Tok: tfbridge.MakeDataSource(mainPkg, containerInstancesMod, "getContainerInstanceShape")},
			"oci_container_instances_container_instance_shapes": {Tok: tfbridge.MakeDataSource(mainPkg, containerInstancesMod, "getContainerInstanceShapes")},
			"oci_container_instances_container_instances":       {Tok: tfbridge.MakeDataSource(mainPkg, containerInstancesMod, "getContainerInstances")},

			"oci_core_app_catalog_listing":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getAppCatalogListing")},
			"oci_core_app_catalog_listing_resource_version":             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getAppCatalogListingResourceVersion")},
			"oci_core_app_catalog_listing_resource_versions":            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getAppCatalogListingResourceVersions")},
			"oci_core_app_catalog_listings":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getAppCatalogListings")},
			"oci_core_app_catalog_subscriptions":                        {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getAppCatalogSubscriptions")},
			"oci_core_block_volume_replica":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBlockVolumeReplica")},
			"oci_core_block_volume_replicas":                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBlockVolumeReplicas")},
			"oci_core_boot_volume":                                      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolume")},
			"oci_core_boot_volume_attachments":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumeAttachments")},
			"oci_core_boot_volume_backup":                               {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumeBackup")},
			"oci_core_boot_volume_backups":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumeBackups")},
			"oci_core_boot_volume_replica":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumeReplica")},
			"oci_core_boot_volume_replicas":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumeReplicas")},
			"oci_core_boot_volumes":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getBootVolumes")},
			"oci_core_byoip_allocated_ranges":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getByoipAllocatedRanges")},
			"oci_core_byoip_range":                                      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getByoipRange")},
			"oci_core_byoip_ranges":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getByoipRanges")},
			"oci_core_cluster_network":                                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getClusterNetwork")},
			"oci_core_cluster_network_instances":                        {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getClusterNetworkInstances")},
			"oci_core_cluster_networks":                                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getClusterNetworks")},
			"oci_core_compute_capacity_reservation":                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeCapacityReservation")},
			"oci_core_compute_capacity_reservation_instance_shapes":     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeCapacityReservationInstanceShapes")},
			"oci_core_compute_capacity_reservation_instances":           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeCapacityReservationInstances")},
			"oci_core_compute_capacity_reservations":                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeCapacityReservations")},
			"oci_core_compute_global_image_capability_schema":           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeGlobalImageCapabilitySchema")},
			"oci_core_compute_global_image_capability_schemas":          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeGlobalImageCapabilitySchemas")},
			"oci_core_compute_global_image_capability_schemas_version":  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeGlobalImageCapabilitySchemasVersion")},
			"oci_core_compute_global_image_capability_schemas_versions": {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeGlobalImageCapabilitySchemasVersions")},
			"oci_core_compute_image_capability_schema":                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeImageCapabilitySchema")},
			"oci_core_compute_image_capability_schemas":                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getComputeImageCapabilitySchemas")},
			"oci_core_console_histories":                                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getConsoleHistories")},
			"oci_core_console_history_data":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getConsoleHistoryData")},
			"oci_core_cpe_device_shape":                                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCpeDeviceShape")},
			"oci_core_cpe_device_shapes":                                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCpeDeviceShapes")},
			"oci_core_cpes":                                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCpes")},
			"oci_core_cross_connect":                                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnect")},
			"oci_core_cross_connect_group":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnectGroup")},
			"oci_core_cross_connect_groups":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnectGroups")},
			"oci_core_cross_connect_locations":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnectLocations")},
			"oci_core_cross_connect_port_speed_shapes":                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnectPortSpeedShape")},
			"oci_core_cross_connect_status":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnectStatus")},
			"oci_core_cross_connects":                                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCrossConnects")},
			"oci_core_dedicated_vm_host":                                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDedicatedVmHost")},
			"oci_core_dedicated_vm_host_instance_shapes":                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDedicatedVmHostInstanceShapes")},
			"oci_core_dedicated_vm_host_shapes":                         {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDedicatedVmHostShapes")},
			"oci_core_dedicated_vm_hosts":                               {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDedicatedVmHosts")},
			"oci_core_dedicated_vm_hosts_instances":                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDedicatedVmHostInstances")},
			"oci_core_dhcp_options":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDhcpOptions")},
			"oci_core_drg_attachments":                                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgAttachments")},
			"oci_core_drg_route_distribution":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteDistribution")},
			"oci_core_drg_route_distribution_statements":                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteDistributionStatements")},
			"oci_core_drg_route_distributions":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteDistributions")},
			"oci_core_drg_route_table":                                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteRule")},
			"oci_core_drg_route_table_route_rules":                      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteTableRouteRules")},
			"oci_core_drg_route_tables":                                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgRouteTables")},
			"oci_core_drgs":                                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getDrgs")},
			"oci_core_fast_connect_provider_service":                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getFastConnectProviderService")},
			"oci_core_fast_connect_provider_service_key":                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getFastConnectProviderServiceKey")},
			"oci_core_fast_connect_provider_services":                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getFastConnectProviderServices")},
			"oci_core_image":                                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getImage")},
			"oci_core_image_shape":                                      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getImageShape")},
			"oci_core_image_shapes":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getImageShapes")},
			"oci_core_images":                                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getImages")},
			"oci_core_instance":                                         {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstance")},
			"oci_core_instance_configuration":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceConfiguration")},
			"oci_core_instance_configurations":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceConfigurations")},
			"oci_core_instance_console_connections":                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceConsoleConnections")},
			"oci_core_instance_credentials":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceCredentials")},
			"oci_core_instance_devices":                                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceDevices")},
			"oci_core_instance_measured_boot_report":                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceMeasuredBootReport")},
			"oci_core_instance_pool":                                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstancePool")},
			"oci_core_instance_pool_instances":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstancePoolInstances")},
			"oci_core_instance_pool_load_balancer_attachment":           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstancePoolLoadBalancerAttachment")},
			"oci_core_instance_pools":                                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstancePools")},
			"oci_core_instances":                                        {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstances")},
			"oci_core_internet_gateways":                                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInternetGateways")},
			"oci_core_ipsec_algorithm":                                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecAlgorithm")},
			"oci_core_ipsec_config":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConfig")},
			"oci_core_ipsec_connection_tunnel":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConnectionTunnel")},
			"oci_core_ipsec_connection_tunnel_error":                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConnectionTunnelError")},
			"oci_core_ipsec_connection_tunnel_routes":                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConnectionTunnelRoutes")},
			"oci_core_ipsec_connection_tunnels":                         {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConnectionTunnels")},
			"oci_core_ipsec_connections":                                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecConnections")},
			"oci_core_ipsec_status":                                     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpsecStatus")},
			"oci_core_ipv6":                                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpv6")},
			"oci_core_ipv6s":                                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getIpv6s")},
			"oci_core_letter_of_authority":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getLetterOfAuthority")},
			"oci_core_listing_resource_version": {
				Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getListingResourceVersion"),
			},
			"oci_core_listing_resource_versions": {
				Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getListingResourceVersions"),
			},
			"oci_core_local_peering_gateways":                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getLocalPeeringGateways")},
			"oci_core_nat_gateway":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNatGateway")},
			"oci_core_nat_gateways":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNatGateways")},
			"oci_core_network_security_group":                {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNetworkSecurityGroup")},
			"oci_core_network_security_group_security_rules": {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNetworkSecurityGroupSecurityRules")},
			"oci_core_network_security_group_vnics":          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNetworkSecurityGroupVnics")},
			"oci_core_network_security_groups":               {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getNetworkSecurityGroups")},
			"oci_core_peer_region_for_remote_peerings":       {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPeerRegionForRemotePeerings")},
			"oci_core_private_ip":                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPrivateIp")},
			"oci_core_private_ips":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPrivateIps")},
			"oci_core_public_ip":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPublicIp")},
			"oci_core_public_ip_pool":                        {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPublicIpPool")},
			"oci_core_public_ip_pools":                       {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPublicIpPools")},
			"oci_core_public_ips":                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getPublicIps")},
			"oci_core_remote_peering_connections":            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getRemotePeeringConnections")},
			"oci_core_route_tables":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getRouteTables")},
			"oci_core_security_lists":                        {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getSecurityLists")},
			"oci_core_service_gateways":                      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getServiceGateways")},
			"oci_core_services":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getServices")},
			"oci_core_shape": {
				Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getShape"),
			},
			"oci_core_shapes":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getShapes")},
			"oci_core_subnet":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getSubnet")},
			"oci_core_subnets":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getSubnets")},
			"oci_core_tunnel_security_associations":     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getTunnelSecurityAssociations")},
			"oci_core_vcn":                              {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVcn")},
			"oci_core_vcn_dns_resolver_association":     {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCnvDnsResolverAssociation")},
			"oci_core_vcns":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVcns")},
			"oci_core_virtual_circuit":                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVirtualCircuit")},
			"oci_core_virtual_circuit_bandwidth_shapes": {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVirtualCircuitBandwidthShapes")},
			"oci_core_virtual_circuit_public_prefixes":  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVirtualCircuitPublicPrefixes")},
			"oci_core_virtual_circuits":                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVirtualCircuits")},
			"oci_core_virtual_networks": {
				Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVirtualNetworks"),
			},
			"oci_core_vlan":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVlan")},
			"oci_core_vlans":                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVlans")},
			"oci_core_vnic":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVnic")},
			"oci_core_vnic_attachments":                 {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVnicAttachments")},
			"oci_core_volume":                           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolume")},
			"oci_core_volume_attachments":               {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeAttachments")},
			"oci_core_volume_backup_policies":           {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeBackupPolicies")},
			"oci_core_volume_backup_policy_assignments": {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeBackupPolicyAssignments")},
			"oci_core_volume_backups":                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeBackups")},
			"oci_core_volume_group_backups":             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeGroupBackups")},
			"oci_core_volume_group_replica":             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeGroupReplica")},
			"oci_core_volume_group_replicas":            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeGroupReplicas")},
			"oci_core_volume_groups":                    {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumeGroups")},
			"oci_core_volumes":                          {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVolumes")},
			"oci_core_capture_filter":                   {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCaptureFilter")},
			"oci_core_capture_filters":                  {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getCaptureFilters")},
			"oci_core_vtap":                             {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVtap")},
			"oci_core_vtaps":                            {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getVtaps")},
			"oci_core_instance_maintenance_reboot":      {Tok: tfbridge.MakeDataSource(mainPkg, coreMod, "getInstanceMaintenanceReboot")},

			"oci_data_labeling_service_annotation_format":  {Tok: tfbridge.MakeDataSource(mainPkg, dataLabellingServiceMod, "getAnnotationFormat")},
			"oci_data_labeling_service_annotation_formats": {Tok: tfbridge.MakeDataSource(mainPkg, dataLabellingServiceMod, "getAnnotationFormats")},
			"oci_data_labeling_service_dataset":            {Tok: tfbridge.MakeDataSource(mainPkg, dataLabellingServiceMod, "getDataset")},
			"oci_data_labeling_service_datasets":           {Tok: tfbridge.MakeDataSource(mainPkg, dataLabellingServiceMod, "getDatasets")},

			"oci_data_safe_alert":                                 {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlert")},
			"oci_data_safe_alert_analytic":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlertAnalytic")},
			"oci_data_safe_alert_policies":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlertPolicies")},
			"oci_data_safe_alert_policy":                          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlertPolicy")},
			"oci_data_safe_alert_policy_rule":                     {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlertPolicyRule")},
			"oci_data_safe_alert_policy_rules":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlertPolicyRules")},
			"oci_data_safe_alerts":                                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAlerts")},
			"oci_data_safe_audit_archive_retrieval":               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditArchiveRetrieval")},
			"oci_data_safe_audit_archive_retrievals":              {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditArchiveRetrievals")},
			"oci_data_safe_audit_event":                           {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditEvent")},
			"oci_data_safe_audit_event_analytic":                  {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditEventAnalytic")},
			"oci_data_safe_audit_events":                          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditEvents")},
			"oci_data_safe_audit_policies":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditPolicies")},
			"oci_data_safe_audit_policy":                          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditPolicy")},
			"oci_data_safe_audit_profile":                         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfile")},
			"oci_data_safe_audit_profile_analytic":                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfileAnalytic")},
			"oci_data_safe_audit_profile_available_audit_volume":  {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfileAvailableAuditVolume")},
			"oci_data_safe_audit_profile_available_audit_volumes": {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfileAvailableAuditVolumes")},
			"oci_data_safe_audit_profile_collected_audit_volume":  {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfileCollectedAuditVolume")},
			"oci_data_safe_audit_profile_collected_audit_volumes": {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfileCollectedAuditVolumes")},
			"oci_data_safe_audit_profiles":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditProfiles")},
			"oci_data_safe_audit_trail":                           {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditTrail")},
			"oci_data_safe_audit_trail_analytic":                  {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditTrailAnalytic")},
			"oci_data_safe_audit_trails":                          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getAuditTrails")},
			"oci_data_safe_compatible_formats_for_data_type":      {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getCompatibleFormatsForDataType")},
			"oci_data_safe_compatible_formats_for_sensitive_type": {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getCompatibleFormatsForSensitiveType")},
			"oci_data_safe_data_safe_configuration":               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint":            {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDataSafePrivateEndpoint")},
			"oci_data_safe_data_safe_private_endpoints":           {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDataSafePrivateEndpoints")},
			"oci_data_safe_discovery_analytic":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDiscoveryAnalytic")},
			"oci_data_safe_discovery_analytics":                   {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDiscoveryAnalytics")},
			"oci_data_safe_discovery_job":                         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDiscoveryJob")},
			"oci_data_safe_discovery_jobs_result":                 {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDiscoveryJobsResult")},
			"oci_data_safe_discovery_jobs_results":                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getDiscoveryJobsResults")},
			"oci_data_safe_library_masking_format":                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getLibraryMaskingFormat")},
			"oci_data_safe_library_masking_formats":               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getLibraryMaskingFormats")},
			"oci_data_safe_list_user_grants":                      {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getListUserGrants")},
			"oci_data_safe_masking_analytic":                      {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingAnalytic")},
			"oci_data_safe_masking_analytics":                     {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingAnalytics")},
			"oci_data_safe_masking_policies":                      {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingPolicies")},
			"oci_data_safe_masking_policies_masking_column":       {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingPoliciesMaskingColumn")},
			"oci_data_safe_masking_policies_masking_columns":      {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingPoliciesMaskingColumns")},
			"oci_data_safe_masking_policy":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingPolicy")},
			"oci_data_safe_masking_report":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingReport")},
			"oci_data_safe_masking_reports":                       {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingReports")},
			"oci_data_safe_masking_reports_masked_column":         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingReportsMaskedColumn")},
			"oci_data_safe_masking_reports_masked_columns":        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getMaskingReportMaskedColumns")},
			"oci_data_safe_on_prem_connector":                     {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getOnpremConnector")},
			"oci_data_safe_on_prem_connectors":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getOnpremConnectors")},
			"oci_data_safe_report":                                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getReport")},
			"oci_data_safe_report_content":                        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getReportContent")},
			"oci_data_safe_report_definition":                     {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getReportDefinition")},
			"oci_data_safe_report_definitions":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getReportDefinitions")},
			"oci_data_safe_reports":                               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getReports")},
			"oci_data_safe_security_assessment":                   {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSecurityAssessment")},
			"oci_data_safe_security_assessment_comparison":        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSecurityAssessmentComparison")},
			"oci_data_safe_security_assessment_finding": {
				Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSecurityAssessmentFinding"),
			},
			"oci_data_safe_security_assessment_findings":            {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSecurityAssessmentFindings")},
			"oci_data_safe_security_assessments":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSecurityAssessments")},
			"oci_data_safe_sensitive_data_model":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveDataModel")},
			"oci_data_safe_sensitive_data_models":                   {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveDataModels")},
			"oci_data_safe_sensitive_data_models_sensitive_column":  {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveDataModelsSensitiveColumn")},
			"oci_data_safe_sensitive_data_models_sensitive_columns": {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveDataModelsSensitiveColumns")},
			"oci_data_safe_sensitive_type":                          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveType")},
			"oci_data_safe_sensitive_types":                         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getSensitiveTypes")},
			"oci_data_safe_target_alert_policy_association":         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetAlertPolicyAssociation")},
			"oci_data_safe_target_alert_policy_associations":        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetAlertPolicyAssociations")},
			"oci_data_safe_target_database":                         {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabase")},
			"oci_data_safe_target_database_role": {
				Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabaseRole"),
			},
			"oci_data_safe_target_database_roles":          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabaseRoles")},
			"oci_data_safe_target_databases":               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabases")},
			"oci_data_safe_target_databases_columns":       {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabasesColumns")},
			"oci_data_safe_target_databases_schemas":       {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabasesSchemas")},
			"oci_data_safe_target_databases_tables":        {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getTargetDatabasesTables")},
			"oci_data_safe_user_assessment":                {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getUserAssessment")},
			"oci_data_safe_user_assessment_comparison":     {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getUserAssessmentComparison")},
			"oci_data_safe_user_assessment_user_analytics": {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getUserAssessmentUserAnalytics")},
			"oci_data_safe_user_assessment_users":          {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getUserAssessmentUsers")},
			"oci_data_safe_user_assessments":               {Tok: tfbridge.MakeDataSource(mainPkg, dataSafeMod, "getUserAssessments")},

			"oci_database_autonomous_container_database":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association":  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousContainerDatabaseDataguardAssociation")},
			"oci_database_autonomous_container_database_dataguard_associations": {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousContainerDatabaseDataguardAssociations")},
			"oci_database_autonomous_container_databases":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousContainerDatabases")},
			"oci_database_autonomous_container_patches":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousContainerPatches")},
			"oci_database_autonomous_database":                                  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabase")},
			"oci_database_autonomous_database_backup":                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseBackup")},
			"oci_database_autonomous_database_backups":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseBackups")},
			"oci_database_autonomous_database_dataguard_association":            {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseDataguardAssociation")},
			"oci_database_autonomous_database_dataguard_associations":           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseDataguardAssociations")},
			"oci_database_autonomous_database_instance_wallet_management":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_refreshable_clones":               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseRefreshableClones")},
			"oci_database_autonomous_database_regional_wallet_management":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabaseWallet")},
			"oci_database_autonomous_databases":                                 {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabases")},
			"oci_database_autonomous_databases_clones":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDatabasesClones")},
			"oci_database_autonomous_db_preview_versions":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDbPreviewVersions")},
			"oci_database_autonomous_db_versions":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousDbVersions")},
			"oci_database_autonomous_exadata_infrastructure":                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousExadataInfrastructure")},
			"oci_database_autonomous_exadata_infrastructure_ocpu":               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousExadataInfrastructureOcpu")},
			"oci_database_autonomous_exadata_infrastructure_shapes":             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousExadataInfrastructureShapes")},
			"oci_database_autonomous_exadata_infrastructures":                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousExadataInfrastructures")},
			"oci_database_autonomous_patch":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousPatch")},
			"oci_database_autonomous_vm_cluster":                                {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousVmCluster")},
			"oci_database_autonomous_vm_clusters":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousVmClusters")},
			"oci_database_backup_destination":                                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getBackupDestination")},
			"oci_database_backup_destinations":                                  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getBackupDestinations")},
			"oci_database_backups":                                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getBackups")},
			"oci_database_cloud_autonomous_vm_cluster":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudAutonomousVmCluster")},
			"oci_database_cloud_autonomous_vm_clusters":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudAutonomousVmClusters")},
			"oci_database_cloud_exadata_infrastructure":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudExadataInfrastructure")},
			"oci_database_cloud_exadata_infrastructures":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudExadataInfrastructures")},
			"oci_database_cloud_exadata_infrastructure_un_allocated_resource":   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudExadataInfrastructureUnAllocatedResource")},
			"oci_database_cloud_vm_cluster":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudVmCluster")},
			"oci_database_cloud_vm_cluster_iorm_config":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudVmClusterIormConfig")},
			"oci_database_cloud_vm_clusters":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getCloudVmClusters")},
			"oci_database_data_guard_association":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDataGuardAssociation")},
			"oci_database_data_guard_associations":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDataGuardAssociations")},
			"oci_database_database":                                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabase")},
			"oci_database_database_pdb_conversion_history_entries":              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabasePdbConversionHistoryEntries")},
			"oci_database_database_pdb_conversion_history_entry":                {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabasePdbConversionHistoryEntry")},
			"oci_database_database_software_image":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseSoftwareImage")},
			"oci_database_database_software_images":                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseSoftwareImages")},
			"oci_database_database_upgrade_history_entries":                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseUpgradeHistoryEntries")},
			"oci_database_database_upgrade_history_entry":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseUpgradeHistoryEntry")},
			"oci_database_databases":                                            {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabases")},
			"oci_database_db_home":                                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbHome")},
			"oci_database_db_home_patch_history_entries":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbHomePatchHistoryEntries")},
			"oci_database_db_home_patches":                                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbHomePatches")},
			"oci_database_db_homes":                                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbHomes")},
			"oci_database_db_node":                                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbNode")},
			"oci_database_db_node_console_connection":                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbNodeConsoleConnection")},
			"oci_database_db_node_console_connections":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbNodeConsoleConnections")},
			"oci_database_db_nodes":                                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbNodes")},
			"oci_database_db_server":                                            {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbServer")},
			"oci_database_db_servers":                                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbServers")},
			"oci_database_db_system_patch_history_entries":                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemHistoryEntries")},
			"oci_database_db_system_patches":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemPatches")},
			"oci_database_db_system_shapes":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemShapes")},
			"oci_database_db_systems":                                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystems")},
			"oci_database_db_versions":                                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbVersions")},
			"oci_database_exadata_infrastructure":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExadataInfrastructure")},
			"oci_database_exadata_infrastructure_download_config_file":          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExadataInfrastructureDownloadConfigFile")},
			"oci_database_exadata_infrastructures":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExadataInfrastructures")},
			"oci_database_exadata_iorm_config":                                  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExadataIormConfig")},
			"oci_database_external_container_database":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalContainerDatabase")},
			"oci_database_external_container_databases":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalContainerDatabases")},
			"oci_database_external_database_connector":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalDatabaseConnector")},
			"oci_database_external_database_connectors":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalDatabaseConnectors")},
			"oci_database_external_non_container_database":                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalNonContainerDatabase")},
			"oci_database_external_non_container_databases":                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalNonContainerDatabases")},
			"oci_database_external_pluggable_database":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalPluggableDatabase")},
			"oci_database_external_pluggable_databases":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getExternalPluggableDatabases")},
			"oci_database_flex_components":                                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getFlexComponents")},
			"oci_database_gi_versions":                                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getGiVersions")},
			"oci_database_infrastructure_target_version":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getInfrastructureTargetVersion")},
			"oci_database_key_store":                                            {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getKeyStore")},
			"oci_database_key_stores":                                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getKeyStores")},
			"oci_database_maintenance_run":                                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getMaintenanceRun")},
			"oci_database_maintenance_runs":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getMaintenanceRuns")},
			"oci_database_management_managed_database_preferred_credential":     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getManagedPreferredCredential")},
			"oci_database_management_managed_database_preferred_credentials":    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getManagedPreferredCredentials")},
			"oci_database_pluggable_database":                                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getPluggableDatabase")},
			"oci_database_pluggable_databases":                                  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getPluggableDatabases")},
			"oci_database_vm_cluster":                                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmCluster")},
			"oci_database_vm_cluster_network":                                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterNetwork")},
			"oci_database_vm_cluster_network_download_config_file":              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterNetworkDownloadConfigFile")},
			"oci_database_vm_cluster_networks":                                  {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterNetworks")},
			"oci_database_vm_cluster_patch":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterPatch")},
			"oci_database_vm_cluster_patch_history_entries":                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterPatchHistoryEntries")},
			"oci_database_vm_cluster_patch_history_entry":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterPatchHistoryEntry")},
			"oci_database_vm_cluster_patches":                                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterPatches")},
			"oci_database_vm_cluster_recommended_network":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterRecommendedNetwork")},
			"oci_database_vm_cluster_update":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterUpdate")},
			"oci_database_vm_cluster_update_history_entries":                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterUpdateHistoryEntries")},
			"oci_database_vm_cluster_update_history_entry":                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterUpdateHistoryEntry")},
			"oci_database_vm_cluster_updates":                                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusterUpdates")},
			"oci_database_vm_clusters":                                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getVmClusters")},
			"oci_database_autonomous_database_character_sets":                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getAutonomousCharacterSets")},
			"oci_database_db_system_compute_performances":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemComputePerformances")},
			"oci_database_db_system_storage_performances":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemStoragePerformances")},
			"oci_database_db_systems_upgrade_history_entries":                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemsUpgradeHistoryEntries")},
			"oci_database_db_systems_upgrade_history_entry":                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDbSystemsUpgradeHistoryEntry")},
			"oci_database_maintenance_run_histories":                            {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseMaintenanceRunHistories")},
			"oci_database_maintenance_run_history":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseMod, "getDatabaseMaintenanceRunHistory")},

			"oci_database_management_db_management_private_endpoint":                      {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getDbManagementPrivateEndpoint")},
			"oci_database_management_db_management_private_endpoint_associated_database":  {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getDbManagementPrivateEndpointAssociatedDatabase")},
			"oci_database_management_db_management_private_endpoint_associated_databases": {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getDbManagementPrivateEndpointAssociatedDatabases")},
			"oci_database_management_db_management_private_endpoints":                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getDbManagementPrivateEndpoints")},
			"oci_database_management_job_executions_status":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getJobExecutionsStatus")},
			"oci_database_management_job_executions_statuses":                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getJobExecutionsStatuses")},
			"oci_database_management_managed_database":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabase")},
			"oci_database_management_managed_database_group":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseGroup")},
			"oci_database_management_managed_database_groups":                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseGroups")},
			"oci_database_management_managed_database_sql_tuning_advisor_task":            {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTask")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks":           {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasks")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparision": { //nolint:misspell
				Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison"),
			},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_finding":              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksFinding")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_findings":             {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksFindings")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_recommendation":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksRecommendation")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_recommendations":      {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksRecommendations")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_sql_execution_plan":   {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksSqlExecutionPlan")},
			"oci_database_management_managed_database_sql_tuning_advisor_tasks_summary_report":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningAdvisorTasksSummaryReport")},
			"oci_database_management_managed_database_user":                                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUser")},
			"oci_database_management_managed_database_user_consumer_group_privilege":                 {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserConsumerGroupPrivilege")},
			"oci_database_management_managed_database_user_consumer_group_privileges":                {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserConsumerGroupPrivileges")},
			"oci_database_management_managed_database_user_data_access_container":                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserDataAccessContainer")},
			"oci_database_management_managed_database_user_data_access_containers":                   {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserDataAccessContainers")},
			"oci_database_management_managed_database_user_object_privilege":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserObjectPrivilege")},
			"oci_database_management_managed_database_user_object_privileges":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserObjectPrivileges")},
			"oci_database_management_managed_database_user_proxied_for_user":                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserProxiedForUser")},
			"oci_database_management_managed_database_user_proxied_for_users":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserProxiedForUsers")},
			"oci_database_management_managed_database_user_role":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserRole")},
			"oci_database_management_managed_database_user_roles":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUserRoles")},
			"oci_database_management_managed_database_users":                                         {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseUsers")},
			"oci_database_management_managed_databases":                                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabases")},
			"oci_database_management_managed_databases_asm_properties":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesAsmProperties")},
			"oci_database_management_managed_databases_asm_property":                                 {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesAsmProperty")},
			"oci_database_management_managed_databases_database_parameter":                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesDatabaseParameter")},
			"oci_database_management_managed_databases_database_parameters":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesDatabaseParameters")},
			"oci_database_management_managed_databases_user_proxy_user":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesUserProxyUser")},
			"oci_database_management_managed_databases_user_proxy_users":                             {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesUserProxyUsers")},
			"oci_database_management_managed_databases_user_system_privilege":                        {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesUserSystemPrivilege")},
			"oci_database_management_managed_databases_user_system_privileges":                       {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabasesUserSystemPrivileges")},
			"oci_database_management_managed_database_addm_task":                                     {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAddmTask")},
			"oci_database_management_managed_database_addm_tasks":                                    {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAddmTasks")},
			"oci_database_management_managed_database_alert_log_count":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAlertLogCount")},
			"oci_database_management_managed_database_alert_log_counts":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAlertLogCounts")},
			"oci_database_management_managed_database_attention_log_count":                           {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAttentionLogCount")},
			"oci_database_management_managed_database_attention_log_counts":                          {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseAttentionLogCounts")},
			"oci_database_management_managed_database_sql_tuning_set":                                {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningSet")},
			"oci_database_management_managed_database_sql_tuning_sets":                               {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseSqlTuningSets")},
			"oci_database_management_managed_database_optimizer_statistics_advisor_execution":        {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsAdvisorExecution")},
			"oci_database_management_managed_database_optimizer_statistics_advisor_execution_script": {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsAdvisorExecutionScript")},
			"oci_database_management_managed_database_optimizer_statistics_advisor_executions":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsAdvisorExecutions")},
			"oci_database_management_managed_database_optimizer_statistics_collection_aggregations":  {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsCollectionAggregations")},
			"oci_database_management_managed_database_optimizer_statistics_collection_operation":     {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsCollectionOperation")},
			"oci_database_management_managed_database_optimizer_statistics_collection_operations":    {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseOptimizerStatisticsCollectionOperations")},
			"oci_database_management_managed_database_table_statistics":                              {Tok: tfbridge.MakeDataSource(mainPkg, databaseManagementMod, "getManagedDatabaseTableStatistics")},

			"oci_database_migration_job_advisor_report":     {Tok: tfbridge.MakeDataSource(mainPkg, databaseMigrationMod, "getJobAdvisorReport")},
			"oci_database_migration_job_output":             {Tok: tfbridge.MakeDataSource(mainPkg, databaseMigrationMod, "getJobOutput")},
			"oci_database_migration_migration_object_types": {Tok: tfbridge.MakeDataSource(mainPkg, databaseMigrationMod, "getMigrationObjectTypes")},

			"oci_database_tools_database_tools_connection":        {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsConnection")},
			"oci_database_tools_database_tools_connections":       {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsConnections")},
			"oci_database_tools_database_tools_endpoint_service":  {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsEndpointService")},
			"oci_database_tools_database_tools_endpoint_services": {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsEndpointServices")},
			"oci_database_tools_database_tools_private_endpoint":  {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsPrivateEndpoint")},
			"oci_database_tools_database_tools_private_endpoints": {Tok: tfbridge.MakeDataSource(mainPkg, databaseToolsMod, "getDatabaseToolsPrivateEndpoints")},

			"oci_datacatalog_catalog":                   {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalog")},
			"oci_datacatalog_catalog_private_endpoint":  {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalogPrivateEndpoint")},
			"oci_datacatalog_catalog_private_endpoints": {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalogPrivateEndpoints")},
			"oci_datacatalog_catalog_type":              {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalogType")},
			"oci_datacatalog_catalog_types":             {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalogTypes")},
			"oci_datacatalog_catalogs":                  {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getCatalogs")},
			"oci_datacatalog_connection":                {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getConnection")},
			"oci_datacatalog_connections":               {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getConnections")},
			"oci_datacatalog_data_asset":                {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getDataAsset")},
			"oci_datacatalog_data_assets":               {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getDataAssets")},
			"oci_datacatalog_metastore":                 {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getMetastore")},
			"oci_datacatalog_metastores":                {Tok: tfbridge.MakeDataSource(mainPkg, dataCatalogMod, "getMetastores")},

			"oci_dataflow_application":       {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getApplication")},
			"oci_dataflow_applications":      {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getApplications")},
			"oci_dataflow_invoke_run":        {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getInvokeRun")},
			"oci_dataflow_invoke_runs":       {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getInvokeRuns")},
			"oci_dataflow_private_endpoint":  {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getPrivateEndpoint")},
			"oci_dataflow_private_endpoints": {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getPrivateEndpoints")},
			"oci_dataflow_run_log":           {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getRunLog")},
			"oci_dataflow_run_logs":          {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getRunLogs")},
			"oci_dataflow_run_statement":     {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getRunStatement")},
			"oci_dataflow_run_statements":    {Tok: tfbridge.MakeDataSource(mainPkg, dataFlowMod, "getRunStatements")},

			"oci_dataintegration_workspace":          {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspace")},
			"oci_dataintegration_workspaces":         {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspaces")},
			"oci_dataintegration_workspace_folder":   {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspaceFolder")},
			"oci_dataintegration_workspace_folders":  {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspaceFolders")},
			"oci_dataintegration_workspace_project":  {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspaceProject")},
			"oci_dataintegration_workspace_projects": {Tok: tfbridge.MakeDataSource(mainPkg, dataIntegrationMod, "getWorkspaceProjects")},

			"oci_datascience_fast_launch_job_configs": {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getFastLaunchJobConfigs")},
			"oci_datascience_job":                     {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getJob")},
			"oci_datascience_job_run":                 {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getJobRun")},
			"oci_datascience_job_runs":                {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getJobRuns")},
			"oci_datascience_job_shapes":              {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getJobShapes")},
			"oci_datascience_jobs":                    {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getJobs")},
			"oci_datascience_model":                   {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModel")},
			"oci_datascience_model_deployment":        {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelDeployment")},
			"oci_datascience_model_deployment_shapes": {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelDeploymentShapes")},
			"oci_datascience_model_deployments":       {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelDeployments")},
			"oci_datascience_model_provenance":        {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelProvenance")},
			"oci_datascience_model_version_set":       {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelVersionSet")},
			"oci_datascience_model_version_sets":      {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModelVersionSets")},
			"oci_datascience_models":                  {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getModels")},
			"oci_datascience_notebook_session":        {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getNotebookSession")},
			"oci_datascience_notebook_session_shapes": {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getNotebookSessionShapes")},
			"oci_datascience_notebook_sessions":       {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getNotebookSessions")},
			"oci_datascience_project":                 {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getProject")},
			"oci_datascience_projects":                {Tok: tfbridge.MakeDataSource(mainPkg, dataScienceMod, "getProjects")},

			"oci_devops_build_pipeline":             {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildPipeline")},
			"oci_devops_build_pipeline_stage":       {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildPipelineStage")},
			"oci_devops_build_pipeline_stages":      {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildPipelineStages")},
			"oci_devops_build_pipelines":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildPipelines")},
			"oci_devops_build_run":                  {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildRun")},
			"oci_devops_build_runs":                 {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getBuildRuns")},
			"oci_devops_connection":                 {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getConnection")},
			"oci_devops_connections":                {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getConnections")},
			"oci_devops_deploy_artifact":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployArtifact")},
			"oci_devops_deploy_artifacts":           {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployArtifacts")},
			"oci_devops_deploy_environment":         {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployEnvironment")},
			"oci_devops_deploy_environments":        {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployEnvironments")},
			"oci_devops_deploy_pipeline":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployPipeline")},
			"oci_devops_deploy_pipelines":           {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployPipelines")},
			"oci_devops_deploy_stage":               {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployStage")},
			"oci_devops_deploy_stages":              {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployStages")},
			"oci_devops_deployment":                 {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployment")},
			"oci_devops_deployments":                {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getDeployments")},
			"oci_devops_project":                    {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getProject")},
			"oci_devops_projects":                   {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getProjects")},
			"oci_devops_repositories":               {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositories")},
			"oci_devops_repository":                 {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepository")},
			"oci_devops_repository_archive_content": {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryArchiveContent")},
			"oci_devops_repository_author":          {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryAuthor")},
			"oci_devops_repository_authors":         {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryAuthors")},
			"oci_devops_repository_commit":          {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryCommit")},
			"oci_devops_repository_commits":         {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryCommits")},
			"oci_devops_repository_diff":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryDiff")},
			"oci_devops_repository_diffs":           {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryDiffs")},
			"oci_devops_repository_file_diff":       {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryFileDiff")},
			"oci_devops_repository_file_line":       {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryFileLine")},
			"oci_devops_repository_mirror_record":   {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryMirrorRecord")},
			"oci_devops_repository_mirror_records":  {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryMirrorRecords")},
			"oci_devops_repository_object":          {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryObject")},
			"oci_devops_repository_object_content":  {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryObjectContent")},
			"oci_devops_repository_path":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryPath")},
			"oci_devops_repository_paths":           {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryPaths")},
			"oci_devops_repository_ref":             {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryRef")},
			"oci_devops_repository_refs":            {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepositoryRefs")},
			"oci_devops_trigger":                    {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getTrigger")},
			"oci_devops_triggers":                   {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getTriggers")},
			"oci_devops_repo_file_line":             {Tok: tfbridge.MakeDataSource(mainPkg, devopsMod, "getRepoFileLine")},

			"oci_disaster_recovery_dr_plan":              {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrPlan")},
			"oci_disaster_recovery_dr_plan_execution":    {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrPlanExecution")},
			"oci_disaster_recovery_dr_plan_executions":   {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrPlanExecutions")},
			"oci_disaster_recovery_dr_plans":             {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrPlans")},
			"oci_disaster_recovery_dr_protection_group":  {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrProtectionGroup")},
			"oci_disaster_recovery_dr_protection_groups": {Tok: tfbridge.MakeDataSource(mainPkg, disasterRecoveryMod, "getDrProtectionGroups")},

			"oci_dns_records":                     {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getRecords")},
			"oci_dns_resolver":                    {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getResolver")},
			"oci_dns_resolver_endpoint":           {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getResolverEndpoint")},
			"oci_dns_resolver_endpoints":          {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getResolverEndpoints")},
			"oci_dns_resolvers":                   {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getResolvers")},
			"oci_dns_rrset":                       {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getRrset")},
			"oci_dns_steering_policies":           {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getSteeringPolicies")},
			"oci_dns_steering_policy":             {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getSteeringPolicy")},
			"oci_dns_steering_policy_attachment":  {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getSteeringPolicyAttachment")},
			"oci_dns_steering_policy_attachments": {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getSteeringPolicyAttachments")},
			"oci_dns_tsig_key":                    {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getTsigKey")},
			"oci_dns_tsig_keys":                   {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getTsigKeys")},
			"oci_dns_view":                        {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getView")},
			"oci_dns_views":                       {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getViews")},
			"oci_dns_zones":                       {Tok: tfbridge.MakeDataSource(mainPkg, dnsMod, "getZones")},

			"oci_email_dkim":          {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getDkim")},
			"oci_email_dkims":         {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getDkims")},
			"oci_email_email_domain":  {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getEmailDomain")},
			"oci_email_email_domains": {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getEmailDomains")},
			"oci_email_sender":        {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getSender")},
			"oci_email_senders":       {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getSenders")},
			"oci_email_suppression":   {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getSuppression")},
			"oci_email_suppressions":  {Tok: tfbridge.MakeDataSource(mainPkg, emailMod, "getSuppressions")},

			"oci_events_rule":  {Tok: tfbridge.MakeDataSource(mainPkg, eventsMod, "getRule")},
			"oci_events_rules": {Tok: tfbridge.MakeDataSource(mainPkg, eventsMod, "getRules")},

			"oci_file_storage_export_sets":         {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getExportSets")},
			"oci_file_storage_exports":             {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getExports")},
			"oci_file_storage_file_systems":        {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getFileSystems")},
			"oci_file_storage_mount_targets":       {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getMountTargets")},
			"oci_file_storage_snapshot":            {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getSnapshot")},
			"oci_file_storage_snapshots":           {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getSnapshots")},
			"oci_file_storage_replication":         {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getReplication")},
			"oci_file_storage_replication_target":  {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getReplicationTarget")},
			"oci_file_storage_replication_targets": {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getReplicationTargets")},
			"oci_file_storage_replications":        {Tok: tfbridge.MakeDataSource(mainPkg, fileStorageMod, "getReplications")},

			"oci_functions_application":  {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getApplication")},
			"oci_functions_applications": {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getApplications")},
			"oci_functions_function":     {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFunction")},
			"oci_functions_functions":    {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFunctions")},

			"oci_fusion_apps_fusion_environment":                             {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironment")},
			"oci_fusion_apps_fusion_environment_admin_user":                  {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentAdminUser")},
			"oci_fusion_apps_fusion_environment_admin_users":                 {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentAdminUsers")},
			"oci_fusion_apps_fusion_environment_data_masking_activities":     {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentDataMaskingActivities")},
			"oci_fusion_apps_fusion_environment_data_masking_activity":       {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentDataMaskingActivity")},
			"oci_fusion_apps_fusion_environment_families":                    {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentFamilies")},
			"oci_fusion_apps_fusion_environment_family":                      {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentFamily")},
			"oci_fusion_apps_fusion_environment_family_limits_and_usage":     {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentFamilyLimitsAndUsage")},
			"oci_fusion_apps_fusion_environment_family_subscription_detail":  {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentFamilySubscriptionDetail")},
			"oci_fusion_apps_fusion_environment_refresh_activities":          {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentRefreshActivities")},
			"oci_fusion_apps_fusion_environment_refresh_activity":            {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentRefreshActivity")},
			"oci_fusion_apps_fusion_environment_scheduled_activities":        {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentScheduledActivities")},
			"oci_fusion_apps_fusion_environment_scheduled_activity":          {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentScheduledActivity")},
			"oci_fusion_apps_fusion_environment_service_attachment":          {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentServiceAttachment")},
			"oci_fusion_apps_fusion_environment_service_attachments":         {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentServiceAttachments")},
			"oci_fusion_apps_fusion_environment_status":                      {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentStatus")},
			"oci_fusion_apps_fusion_environment_time_available_for_refresh":  {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentTimeAvailableForRefresh")},
			"oci_fusion_apps_fusion_environment_time_available_for_refreshs": {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironmentTimeAvailableForRefreshs")},
			"oci_fusion_apps_fusion_environments":                            {Tok: tfbridge.MakeDataSource(mainPkg, functionsMod, "getFusionEnvironments")},

			"oci_generic_artifacts_content_artifact_by_path":          {Tok: tfbridge.MakeDataSource(mainPkg, genericArtifactsContentMod, "getArtifactByPath")},
			"oci_generic_artifacts_content_generic_artifacts_content": {Tok: tfbridge.MakeDataSource(mainPkg, genericArtifactsContentMod, "getGenericArtifactsContent")},

			"oci_golden_gate_database_registration":  {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDatabaseRegistration")},
			"oci_golden_gate_database_registrations": {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDatabaseRegistrations")},
			"oci_golden_gate_deployment":             {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeployment")},
			"oci_golden_gate_deployment_backup":      {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentBackup")},
			"oci_golden_gate_deployment_backups":     {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentBackups")},
			"oci_golden_gate_deployment_upgrade":     {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentUpgrade")},
			"oci_golden_gate_deployment_upgrades":    {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentUpgrades")},
			"oci_golden_gate_deployments":            {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeployments")},

			"oci_golden_gate_connection":             {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getConnection")},
			"oci_golden_gate_connection_assignment":  {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getConnectionAssignment")},
			"oci_golden_gate_connection_assignments": {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getConnectionAssignments")},
			"oci_golden_gate_connections":            {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getConnections")},
			"oci_golden_gate_deployment_type":        {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentType")},
			"oci_golden_gate_deployment_types":       {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getDeploymentTypes")},
			"oci_golden_gate_message":                {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getMessage")},
			"oci_golden_gate_messages":               {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getMessages")},
			"oci_golden_gate_trail_file":             {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getTrailFile")},
			"oci_golden_gate_trail_files":            {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getTrailFiles")},
			"oci_golden_gate_trail_sequence":         {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getTrailSequence")},
			"oci_golden_gate_trail_sequences":        {Tok: tfbridge.MakeDataSource(mainPkg, goldenGateMod, "getTrailSequences")},

			"oci_health_checks_http_monitor":       {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getHttpMonitor")},
			"oci_health_checks_http_monitors":      {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getHttpMonitors")},
			"oci_health_checks_http_probe_results": {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getHttpProbeResults")},
			"oci_health_checks_ping_monitor":       {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getPingMonitor")},
			"oci_health_checks_ping_monitors":      {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getPingMonitors")},
			"oci_health_checks_ping_probe_results": {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getPingProbeResults")},
			"oci_health_checks_vantage_points":     {Tok: tfbridge.MakeDataSource(mainPkg, healthChecksMod, "getVantagePoints")},

			"oci_identity_allowed_domain_license_types":         {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getAllowedDomainLicenseTypes")},
			"oci_identity_api_keys":                             {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getApiKeys")},
			"oci_identity_auth_tokens":                          {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getAuthTokens")},
			"oci_identity_authentication_policy":                {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getAuthenticationPolicy")},
			"oci_identity_availability_domain":                  {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getAvailabilityDomain")},
			"oci_identity_availability_domains":                 {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getAvailabilityDomains")},
			"oci_identity_compartment":                          {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getCompartment")},
			"oci_identity_compartments":                         {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getCompartments")},
			"oci_identity_cost_tracking_tags":                   {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getCostTrackingTags")},
			"oci_identity_customer_secret_keys":                 {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getCustomerSecretKeys")},
			"oci_identity_db_credentials":                       {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getDbCredentials")},
			"oci_identity_domain":                               {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getDomain")},
			"oci_identity_domains":                              {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getDomains")},
			"oci_identity_dynamic_groups":                       {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getDynamicGroups")},
			"oci_identity_fault_domains":                        {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getFaultDomains")},
			"oci_identity_group":                                {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getGroup")},
			"oci_identity_groups":                               {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getGroups")},
			"oci_identity_iam_work_request":                     {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIamWorkRequest")},
			"oci_identity_iam_work_request_errors":              {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIamWorkRequestErrors")},
			"oci_identity_iam_work_request_logs":                {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIamWorkRequestLogs")},
			"oci_identity_iam_work_requests":                    {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIamWorkRequests")},
			"oci_identity_identity_provider_groups":             {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIdentityProviderGroups")},
			"oci_identity_identity_providers":                   {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIdentityProviders")},
			"oci_identity_idp_group_mappings":                   {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getIdpGroupMappings")},
			"oci_identity_network_source":                       {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getNetworkSource")},
			"oci_identity_network_sources":                      {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getNetworkSources")},
			"oci_identity_policies":                             {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getPolicies")},
			"oci_identity_region_subscriptions":                 {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getRegionSubscriptions")},
			"oci_identity_regions":                              {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getRegions")},
			"oci_identity_smtp_credentials":                     {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getSmtpCredentials")},
			"oci_identity_tag":                                  {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTag")},
			"oci_identity_tag_default":                          {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTagDefault")},
			"oci_identity_tag_defaults":                         {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTagDefaults")},
			"oci_identity_tag_namespaces":                       {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTagNamespaces")},
			"oci_identity_tag_standard_tag_namespace_template":  {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTagStandardTagNamespaceTemplate")},
			"oci_identity_tag_standard_tag_namespace_templates": {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTagStandardTagNamespaceTemplates")},
			"oci_identity_tags":                                 {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTags")},
			"oci_identity_tenancy":                              {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getTenancy")},
			"oci_identity_ui_password":                          {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getUiPassword")},
			"oci_identity_user":                                 {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getUser")},
			"oci_identity_user_group_memberships":               {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getUserGroupMemberships")},
			"oci_identity_users":                                {Tok: tfbridge.MakeDataSource(mainPkg, identityMod, "getUsers")},

			"oci_integration_integration_instance":  {Tok: tfbridge.MakeDataSource(mainPkg, integrationMod, "getIntegrationInstance")},
			"oci_integration_integration_instances": {Tok: tfbridge.MakeDataSource(mainPkg, integrationMod, "getIntegrationInstances")},

			"oci_jms_fleet": {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleet")},
			"oci_jms_fleet_advanced_feature_configuration": {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleetAdvancedFeatureConfiguration")},
			"oci_jms_fleet_blocklists":                     {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleetBlocklists")},
			"oci_jms_fleet_crypto_analysis_result":         {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleetCryptoAnalysisResult")},
			"oci_jms_fleet_crypto_analysis_results":        {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleetCryptoAnalysisResults")},
			"oci_jms_fleet_installation_site":              {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getInstallationSite")},
			"oci_jms_fleet_installation_sites":             {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getInstallationSites")},
			"oci_jms_fleets":                               {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getFleets")},
			"oci_jms_list_jre_usage":                       {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getListJreUsage")},
			"oci_jms_summarize_resource_inventory":         {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getSummarizeResourceInventory")},
			"oci_jms_java_families":                        {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getJavaFamilies")},
			"oci_jms_java_family":                          {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getJavaFamily")},
			"oci_jms_java_release":                         {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getJavaRelease")},
			"oci_jms_java_releases":                        {Tok: tfbridge.MakeDataSource(mainPkg, jmsMod, "getJavaReleases")},

			"oci_kms_decrypted_data":     {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getDecryptedData")},
			"oci_kms_encrypted_data":     {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getEncryptedData")},
			"oci_kms_key":                {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getKey")},
			"oci_kms_key_version":        {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getKeyVersion")},
			"oci_kms_key_versions":       {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getKeyVersions")},
			"oci_kms_keys":               {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getKeys")},
			"oci_kms_replication_status": {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getReplicationStatus")},
			"oci_kms_vault":              {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getVault")},
			"oci_kms_vault_replicas":     {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getVaultReplicas")},
			"oci_kms_vault_usage":        {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getVaultUsage")},
			"oci_kms_vaults":             {Tok: tfbridge.MakeDataSource(mainPkg, kmsMod, "getVaults")},

			"oci_license_manager_configuration":                 {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getConfiguration")},
			"oci_license_manager_license_metric":                {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getLicenseMetric")},
			"oci_license_manager_license_record":                {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getLicenseRecord")},
			"oci_license_manager_license_records":               {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getLicenseRecords")},
			"oci_license_manager_product_license":               {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getProductLicense")},
			"oci_license_manager_product_licenses":              {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getProductLicenses")},
			"oci_license_manager_product_license_consumers":     {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getProductLicenseConsumers")},
			"oci_license_manager_top_utilized_product_licenses": {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getTopUtilizedProductLicenses")},
			"oci_license_manager_top_utilized_resources":        {Tok: tfbridge.MakeDataSource(mainPkg, licenseManagerMod, "getTopUtilizedResources")},

			"oci_limits_limit_definitions":     {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getLimitDefinitions")},
			"oci_limits_limit_values":          {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getLimitValues")},
			"oci_limits_quota":                 {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getQuota")},
			"oci_limits_quotas":                {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getQuotas")},
			"oci_limits_resource_availability": {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getResourceAvailability")},
			"oci_limits_services":              {Tok: tfbridge.MakeDataSource(mainPkg, limitsMod, "getServices")},

			"oci_load_balancer_backend_health":                 {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getBackendHealth")},
			"oci_load_balancer_backend_set_health":             {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getBackendSetHealth")},
			"oci_load_balancer_backend_sets":                   {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getBackendSets")},
			"oci_load_balancer_backends":                       {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getBackends")},
			"oci_load_balancer_certificates":                   {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getCertificates")},
			"oci_load_balancer_health":                         {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getHealth")},
			"oci_load_balancer_hostnames":                      {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getHostnames")},
			"oci_load_balancer_listener_rules":                 {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getListenerRules")},
			"oci_load_balancer_load_balancer_routing_policies": {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getLoadBalancerRoutingPolicies")},
			"oci_load_balancer_load_balancer_routing_policy":   {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getLoadBalancerRoutingPolicy")},
			"oci_load_balancer_load_balancers":                 {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getLoadBalancers")},
			"oci_load_balancer_path_route_sets":                {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getPathRouteSets")},
			"oci_load_balancer_policies":                       {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getPolicies")},
			"oci_load_balancer_protocols":                      {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getProtocols")},
			"oci_load_balancer_rule_set":                       {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getRuleSet")},
			"oci_load_balancer_rule_sets":                      {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getRuleSets")},
			"oci_load_balancer_shapes":                         {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getShapes")},
			"oci_load_balancer_ssl_cipher_suite":               {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getSslCipherSuite")},
			"oci_load_balancer_ssl_cipher_suites":              {Tok: tfbridge.MakeDataSource(mainPkg, loadBalancerMod, "getSslCipherSuites")},

			"oci_log_analytics_log_analytics_categories_list":          {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsCategoriesList")},
			"oci_log_analytics_log_analytics_category":                 {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsCategory")},
			"oci_log_analytics_log_analytics_entities":                 {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsEntities")},
			"oci_log_analytics_log_analytics_entities_summary":         {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsEntitiesSummary")},
			"oci_log_analytics_log_analytics_entity":                   {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_entity_topology":          {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsEntityTopology")},
			"oci_log_analytics_log_analytics_log_group":                {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_log_groups":               {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsLogGroups")},
			"oci_log_analytics_log_analytics_log_groups_summary":       {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsLogGroupsSummary")},
			"oci_log_analytics_log_analytics_object_collection_rule":   {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_log_analytics_object_collection_rules":  {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsObjectCollectionRules")},
			"oci_log_analytics_log_analytics_preference":               {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsPreference")},
			"oci_log_analytics_log_analytics_resource_categories_list": {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsResourceCategoriesList")},
			"oci_log_analytics_log_analytics_unprocessed_data_bucket":  {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogAnalyticsUnprocessedDataBucket")},
			"oci_log_analytics_log_sets_count":                         {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getLogSetsCount")},
			"oci_log_analytics_namespace":                              {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespace")},
			"oci_log_analytics_namespace_scheduled_task":               {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceScheduledTask")},
			"oci_log_analytics_namespace_scheduled_tasks":              {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceScheduledTasks")},
			"oci_log_analytics_namespaces":                             {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaces")},

			"oci_log_analytics_namespace_ingest_time_rule":            {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceIngestTimeRule")},
			"oci_log_analytics_namespace_ingest_time_rules":           {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceIngestTimeRules")},
			"oci_log_analytics_namespace_rules":                       {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceRules")},
			"oci_log_analytics_namespace_storage_encryption_key_info": {Tok: tfbridge.MakeDataSource(mainPkg, logAnalyticsMod, "getNamespaceStorageEncryptionKeyInfo")},

			"oci_logging_log":                          {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLog")},
			"oci_logging_log_group":                    {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLogGroup")},
			"oci_logging_log_groups":                   {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLogGroups")},
			"oci_logging_log_saved_search":             {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLogSavedSearch")},
			"oci_logging_log_saved_searches":           {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLogSavedSearches")},
			"oci_logging_logs":                         {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getLogs")},
			"oci_logging_unified_agent_configuration":  {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getUnifiedAgentConfiguration")},
			"oci_logging_unified_agent_configurations": {Tok: tfbridge.MakeDataSource(mainPkg, loggingMod, "getUnifiedAgentConfigurations")},

			"oci_management_agent_management_agent":                            {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgent")},
			"oci_management_agent_management_agent_available_histories":        {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentAvailableHistories")},
			"oci_management_agent_management_agent_count":                      {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentCount")},
			"oci_management_agent_management_agent_get_auto_upgradable_config": {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentGetAutoUpgradableConfig")},
			"oci_management_agent_management_agent_images":                     {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentImages")},
			"oci_management_agent_management_agent_install_key":                {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentInstallKey")},
			"oci_management_agent_management_agent_install_keys":               {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentInstallKeys")},
			"oci_management_agent_management_agent_plugin_count":               {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentPluginCount")},
			"oci_management_agent_management_agent_plugins":                    {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgentPlugins")},
			"oci_management_agent_management_agents":                           {Tok: tfbridge.MakeDataSource(mainPkg, managementAgentMod, "getManagementAgents")},

			"oci_management_dashboard_management_dashboards_export": {Tok: tfbridge.MakeDataSource(mainPkg, managementDashboardMod, "getManagementDashboardsExport")},

			"oci_marketplace_accepted_agreement":         {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getAcceptedAgreement")},
			"oci_marketplace_accepted_agreements":        {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getAcceptedAgreements")},
			"oci_marketplace_categories":                 {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getCategories")},
			"oci_marketplace_listing":                    {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListing")},
			"oci_marketplace_listing_package":            {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListingPackage")},
			"oci_marketplace_listing_package_agreements": {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListingPackageAgreements")},
			"oci_marketplace_listing_packages":           {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListingPackages")},
			"oci_marketplace_listing_taxes":              {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListingTaxes")},
			"oci_marketplace_listings":                   {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getListings")},
			"oci_marketplace_publication":                {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getPublication")},
			"oci_marketplace_publication_package":        {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getPublicationPackage")},
			"oci_marketplace_publication_packages":       {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getPublicationPackages")},
			"oci_marketplace_publications":               {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getPublications")},
			"oci_marketplace_publishers":                 {Tok: tfbridge.MakeDataSource(mainPkg, marketplaceMod, "getPublishers")},

			"oci_media_services_media_asset":                                 {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaAsset")},
			"oci_media_services_media_asset_distribution_channel_attachment": {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaAssetDistributionChannelAttachment")},
			"oci_media_services_media_assets":                                {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaAssets")},
			"oci_media_services_media_workflow":                              {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflow")},
			"oci_media_services_media_workflow_configuration":                {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowConfiguration")},
			"oci_media_services_media_workflow_configurations":               {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowConfigurations")},
			"oci_media_services_media_workflow_job":                          {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowJob")},
			"oci_media_services_media_workflow_job_fact":                     {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowJobFact")},
			"oci_media_services_media_workflow_job_facts":                    {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowJobFacts")},
			"oci_media_services_media_workflow_jobs":                         {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowJobs")},
			"oci_media_services_media_workflow_task_declaration":             {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflowTaskDeclaration")},
			"oci_media_services_media_workflows":                             {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getMediaWorkflows")},
			"oci_media_services_stream_cdn_config":                           {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamCdnConfig")},
			"oci_media_services_stream_cdn_configs":                          {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamCdnConfigs")},
			"oci_media_services_stream_distribution_channel":                 {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamDistributionChannel")},
			"oci_media_services_stream_distribution_channels":                {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamDistributionChannels")},
			"oci_media_services_stream_packaging_config":                     {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamPackagingConfig")},
			"oci_media_services_stream_packaging_configs":                    {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getStreamPackagingConfigs")},
			"oci_media_services_system_media_workflow":                       {Tok: tfbridge.MakeDataSource(mainPkg, mediaServicesMod, "getSystemMediaWorkflow")},

			"oci_metering_computation_configuration":  {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getConfiguration")},
			"oci_metering_computation_custom_table":   {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getCustomTable")},
			"oci_metering_computation_custom_tables":  {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getCustomTables")},
			"oci_metering_computation_queries":        {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getQueries")},
			"oci_metering_computation_query":          {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getQuery")},
			"oci_metering_computation_schedule":       {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getSchedule")},
			"oci_metering_computation_schedules":      {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getSchedules")},
			"oci_metering_computation_scheduled_run":  {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getScheduledRun")},
			"oci_metering_computation_scheduled_runs": {Tok: tfbridge.MakeDataSource(mainPkg, meteringComputationMod, "getScheduledRuns")},

			"oci_monitoring_alarm":                    {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getAlarm")},
			"oci_monitoring_alarm_history_collection": {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getAlarmHistoryCollection")},
			"oci_monitoring_alarm_statuses":           {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getAlarmStatuses")},
			"oci_monitoring_alarms":                   {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getAlarms")},
			"oci_monitoring_metric_data":              {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getMetricData")},
			"oci_monitoring_metrics":                  {Tok: tfbridge.MakeDataSource(mainPkg, monitoringMod, "getMetrics")},
			"oci_mysql_channel":                       {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getChannel")},
			"oci_mysql_channels":                      {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getChannels")},
			"oci_mysql_heat_wave_cluster":             {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getHeatWaveCluster")},
			"oci_mysql_mysql_backup":                  {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlBackup")},
			"oci_mysql_mysql_backups":                 {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlBackups")},
			"oci_mysql_mysql_configuration":           {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlConfiguration")},
			"oci_mysql_mysql_configurations":          {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlConfigurations")},
			"oci_mysql_mysql_db_system":               {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlDbSystem")},
			"oci_mysql_mysql_db_systems":              {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlDbSystems")},
			"oci_mysql_mysql_versions":                {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getMysqlVersion")},
			"oci_mysql_shapes":                        {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getShapes")},

			"oci_mysql_replica":  {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getReplica")},
			"oci_mysql_replicas": {Tok: tfbridge.MakeDataSource(mainPkg, mysqlMod, "getReplicas")},

			"oci_network_load_balancer_backend_health": {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getBackendHealth")},
			"oci_network_load_balancer_backend_set":    {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getBackendSet")},
			"oci_network_load_balancer_backend_set_health": {
				Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getBackendSetHealth"),
			},
			"oci_network_load_balancer_backend_sets":                     {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getBackendSets")},
			"oci_network_load_balancer_backends":                         {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getBackends")},
			"oci_network_load_balancer_listener":                         {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getListener")},
			"oci_network_load_balancer_listeners":                        {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getListeners")},
			"oci_network_load_balancer_network_load_balancer":            {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getNetworkLoadBalancer")},
			"oci_network_load_balancer_network_load_balancer_health":     {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getNetworkLoadBalancerHealth")},
			"oci_network_load_balancer_network_load_balancers":           {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getNetworkLoadBalancers")},
			"oci_network_load_balancer_network_load_balancers_policies":  {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getNetworkLoadBalancersPolicies")},
			"oci_network_load_balancer_network_load_balancers_protocols": {Tok: tfbridge.MakeDataSource(mainPkg, networkLoadBalancerMod, "getNetworkLoadBalancersProtocols")},

			"oci_network_firewall_network_firewall":          {Tok: tfbridge.MakeDataSource(mainPkg, networkFirewallMod, "getNetworkFirewall")},
			"oci_network_firewall_network_firewalls":         {Tok: tfbridge.MakeDataSource(mainPkg, networkFirewallMod, "getNetworkFirewalls")},
			"oci_network_firewall_network_firewall_policies": {Tok: tfbridge.MakeDataSource(mainPkg, networkFirewallMod, "getNetworkFirewallPolicies")},
			"oci_network_firewall_network_firewall_policy":   {Tok: tfbridge.MakeDataSource(mainPkg, networkFirewallMod, "getNetworkFirewallPolicy")},

			"oci_nosql_index":   {Tok: tfbridge.MakeDataSource(mainPkg, nosqlMod, "getIndex")},
			"oci_nosql_indexes": {Tok: tfbridge.MakeDataSource(mainPkg, nosqlMod, "getIndexes")},
			"oci_nosql_table":   {Tok: tfbridge.MakeDataSource(mainPkg, nosqlMod, "getTable")},
			"oci_nosql_tables":  {Tok: tfbridge.MakeDataSource(mainPkg, nosqlMod, "getTables")},

			"oci_objectstorage_bucket":           {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getBucket")},
			"oci_objectstorage_bucket_summaries": {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getBucketSummaries")},
			"oci_objectstorage_namespace":        {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getNamespace")},
			"oci_objectstorage_namespace_metadata": {
				Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getNamespaceMetadata"),
			},
			"oci_objectstorage_object":                  {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getObject")},
			"oci_objectstorage_object_head":             {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getObjectHead")},
			"oci_objectstorage_object_lifecycle_policy": {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getObjectLifecyclePolicy")},
			"oci_objectstorage_object_versions":         {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getObjectVersions")},
			"oci_objectstorage_objects":                 {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getObjects")},
			"oci_objectstorage_preauthrequest":          {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getPreauthrequest")},
			"oci_objectstorage_preauthrequests":         {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getPreauthrequests")},
			"oci_objectstorage_replication_policies":    {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getReplicationPolicies")},
			"oci_objectstorage_replication_policy":      {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getReplicationPolicy")},
			"oci_objectstorage_replication_sources":     {Tok: tfbridge.MakeDataSource(mainPkg, objectStorageMod, "getReplicationSources")},

			"oci_oce_oce_instance":  {Tok: tfbridge.MakeDataSource(mainPkg, oceMod, "getOceInstance")},
			"oci_oce_oce_instances": {Tok: tfbridge.MakeDataSource(mainPkg, oceMod, "getOceInstances")},

			"oci_ocvp_esxi_host":                          {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getExsiHost")},
			"oci_ocvp_esxi_hosts":                         {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getExsiHosts")},
			"oci_ocvp_sddc":                               {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getSddc")},
			"oci_ocvp_sddcs":                              {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getSddcs")},
			"oci_ocvp_supported_host_shapes":              {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getSupportedHostShapes")},
			"oci_ocvp_supported_skus":                     {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getSupportedSkus")},
			"oci_ocvp_supported_vmware_software_versions": {Tok: tfbridge.MakeDataSource(mainPkg, ocvpMod, "getSupportedVmwareSoftwareVersions")},

			"oci_oda_oda_instance":  {Tok: tfbridge.MakeDataSource(mainPkg, odaMod, "getOdaInstance")},
			"oci_oda_oda_instances": {Tok: tfbridge.MakeDataSource(mainPkg, odaMod, "getOdaInstances")},

			"oci_ons_notification_topic":  {Tok: tfbridge.MakeDataSource(mainPkg, onsMod, "getNotificationTopic")},
			"oci_ons_notification_topics": {Tok: tfbridge.MakeDataSource(mainPkg, onsMod, "getNotificationTopics")},
			"oci_ons_subscription":        {Tok: tfbridge.MakeDataSource(mainPkg, onsMod, "getSubscription")},
			"oci_ons_subscriptions":       {Tok: tfbridge.MakeDataSource(mainPkg, onsMod, "getSubscriptions")},

			"oci_onesubscription_aggregated_computed_usages":   {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getAggregatedComputedUsages")},
			"oci_onesubscription_billing_schedules":            {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getBillingSchedules")},
			"oci_onesubscription_commitment":                   {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getCommitment")},
			"oci_onesubscription_commitments":                  {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getCommitments")},
			"oci_onesubscription_computed_usage":               {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getComputedUsage")},
			"oci_onesubscription_computed_usages":              {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getComputedUsages")},
			"oci_onesubscription_invoice_line_computed_usages": {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getInvoiceLineComputedUsages")},
			"oci_onesubscription_invoices":                     {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getInvoices")},
			"oci_onesubscription_organization_subscriptions":   {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getOrganizationSubscriptions")},
			"oci_onesubscription_ratecards":                    {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getRatecards")},
			"oci_onesubscription_subscribed_service":           {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getSubscribedService")},
			"oci_onesubscription_subscribed_services":          {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getSubscribedServices")},
			"oci_onesubscription_subscriptions":                {Tok: tfbridge.MakeDataSource(mainPkg, oneSubscriptionMod, "getSubscriptions")},

			"oci_opensearch_opensearch_cluster":  {Tok: tfbridge.MakeDataSource(mainPkg, opensearchMod, "getOpensearchCluster")},
			"oci_opensearch_opensearch_clusters": {Tok: tfbridge.MakeDataSource(mainPkg, opensearchMod, "getOpensearchClusters")},
			"oci_opensearch_opensearch_version":  {Tok: tfbridge.MakeDataSource(mainPkg, opensearchMod, "getOpensearchVersion")},
			"oci_opensearch_opensearch_versions": {Tok: tfbridge.MakeDataSource(mainPkg, opensearchMod, "getOpensearchVersions")},

			"oci_opa_opa_instance":  {Tok: tfbridge.MakeDataSource(mainPkg, opaMod, "getOpaInstance")},
			"oci_opa_opa_instances": {Tok: tfbridge.MakeDataSource(mainPkg, opaMod, "getOpaInstances")},

			"oci_operator_access_control_access_request":               {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getAccessRequest")},
			"oci_operator_access_control_access_request_history":       {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getAccessRequestHistory")},
			"oci_operator_access_control_access_requests":              {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getAccessRequests")},
			"oci_operator_access_control_operator_action":              {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getAction")},
			"oci_operator_access_control_operator_actions":             {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getActions")},
			"oci_operator_access_control_operator_control":             {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getControl")},
			"oci_operator_access_control_operator_control_assignment":  {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getControlAssignment")},
			"oci_operator_access_control_operator_control_assignments": {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getControlAssignments")},
			"oci_operator_access_control_operator_controls":            {Tok: tfbridge.MakeDataSource(mainPkg, operatorAccessControlMod, "getControls")},

			"oci_opsi_awr_hub":                                              {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getAwrHub")},
			"oci_opsi_awr_hub_awr_snapshot":                                 {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getAwrHubAwrSnapshot")},
			"oci_opsi_awr_hub_awr_snapshots":                                {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getAwrHubAwrSnapshots")},
			"oci_opsi_awr_hub_awr_sources_summary":                          {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getAwrHubAwrSourcesSummary")},
			"oci_opsi_awr_hubs":                                             {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getAwrHubs")},
			"oci_opsi_database_insight":                                     {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getDatabaseInsight")},
			"oci_opsi_database_insights":                                    {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getDatabaseInsights")},
			"oci_opsi_enterprise_manager_bridge":                            {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getEnterpriseManagerBridge")},
			"oci_opsi_enterprise_manager_bridges":                           {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getEnterpriseManagerBridges")},
			"oci_opsi_exadata_insight":                                      {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getExadataInsight")},
			"oci_opsi_exadata_insights":                                     {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getExadataInsights")},
			"oci_opsi_host_insight":                                         {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getHostInsight")},
			"oci_opsi_host_insights":                                        {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getHostInsights")},
			"oci_opsi_operations_insights_private_endpoint":                 {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsPrivateEndpoint")},
			"oci_opsi_operations_insights_private_endpoints":                {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsPrivateEndpoints")},
			"oci_opsi_operations_insights_warehouse":                        {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsWarehouse")},
			"oci_opsi_operations_insights_warehouse_resource_usage_summary": {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsWarehouseResourceUsageSummary")},
			"oci_opsi_operations_insights_warehouse_user":                   {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsWarehouseUser")},
			"oci_opsi_operations_insights_warehouse_users":                  {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsWarehouseUsers")},
			"oci_opsi_operations_insights_warehouses":                       {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getOperationsInsightsWarehouses")},
			"oci_opsi_importable_agent_entities":                            {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getImportableAgentEntities")},
			"oci_opsi_importable_agent_entity":                              {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getImportableAgentEntity")},
			"oci_opsi_importable_compute_entities":                          {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getImportableComputeEntities")},
			"oci_opsi_importable_compute_entity":                            {Tok: tfbridge.MakeDataSource(mainPkg, opsiMod, "getImportableComputeEntity")},

			"oci_optimizer_categories":                {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getCategories")},
			"oci_optimizer_category":                  {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getCategory")},
			"oci_optimizer_enrollment_status":         {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getEnrollmentStatus")},
			"oci_optimizer_enrollment_statuses":       {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getEnrollmentStatuses")},
			"oci_optimizer_histories":                 {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getHistories")},
			"oci_optimizer_profile":                   {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getProfile")},
			"oci_optimizer_profile_level":             {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getProfileLevel")},
			"oci_optimizer_profile_levels":            {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getProfileLevels")},
			"oci_optimizer_profiles":                  {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getProfiles")},
			"oci_optimizer_recommendation":            {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getRecommendation")},
			"oci_optimizer_recommendation_strategies": {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getRecommendationStrategies")},
			"oci_optimizer_recommendation_strategy":   {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getRecommendationStrategy")},
			"oci_optimizer_recommendations":           {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getRecommendations")},
			"oci_optimizer_resource_action":           {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getResourceAction")},
			"oci_optimizer_resource_actions":          {Tok: tfbridge.MakeDataSource(mainPkg, optimizerMod, "getResourceActions")},

			"oci_osmanagement_managed_instance":                      {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstance")},
			"oci_osmanagement_managed_instance_event_report":         {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstanceEventReport")},
			"oci_osmanagement_managed_instance_group":                {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_groups":               {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstanceGroups")},
			"oci_osmanagement_managed_instances":                     {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstances")},
			"oci_osmanagement_software_source":                       {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getSoftwareSource")},
			"oci_osmanagement_software_sources":                      {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getSoftwareSources")},
			"oci_osmanagement_managed_instance_module_streams":       {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstanceModuleStreams")},
			"oci_osmanagement_managed_instance_stream_profiles":      {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getManagedInstanceStreamProfile")},
			"oci_osmanagement_software_source_module_stream":         {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getSoftwareSourceModuleStream")},
			"oci_osmanagement_software_source_module_stream_profile": {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getSoftwareSourceModuleStreamProfile")},
			"oci_osmanagement_software_source_stream_profiles":       {Tok: tfbridge.MakeDataSource(mainPkg, osManagementMod, "getSoftwareSourceStreamProfile")},

			"oci_osp_gateway_invoice":                {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getInvoice")},
			"oci_osp_gateway_invoices":               {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getInvoices")},
			"oci_osp_gateway_invoices_invoice_line":  {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getInvoicesInvoiceLine")},
			"oci_osp_gateway_invoices_invoice_lines": {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getInvoicesInvoiceLines")},
			"oci_osp_gateway_subscription":           {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getSubscription")},
			"oci_osp_gateway_subscriptions":          {Tok: tfbridge.MakeDataSource(mainPkg, ospGatewayMod, "getSubscriptions")},

			"oci_osub_billing_schedule_billing_schedules": {Tok: tfbridge.MakeDataSource(mainPkg, osubBillingScheduleMod, "getBillingSchedule")},

			"oci_osub_organization_subscription_organization_subscriptions": {Tok: tfbridge.MakeDataSource(mainPkg, osubOrganizationSubscriptionMod, "getOrganizationSubscriptions")},

			"oci_osub_subscription_commitment":    {Tok: tfbridge.MakeDataSource(mainPkg, osubSubscriptionMod, "getCommitment")},
			"oci_osub_subscription_commitments":   {Tok: tfbridge.MakeDataSource(mainPkg, osubSubscriptionMod, "getCommitments")},
			"oci_osub_subscription_ratecards":     {Tok: tfbridge.MakeDataSource(mainPkg, osubSubscriptionMod, "getRatecards")},
			"oci_osub_subscription_subscriptions": {Tok: tfbridge.MakeDataSource(mainPkg, osubSubscriptionMod, "getSubscriptions")},

			"oci_osub_usage_computed_usage":             {Tok: tfbridge.MakeDataSource(mainPkg, osubUsageMod, "getComputedUsage")},
			"oci_osub_usage_computed_usage_aggregateds": {Tok: tfbridge.MakeDataSource(mainPkg, osubUsageMod, "getCommitmentAggregateds")},
			"oci_osub_usage_computed_usages":            {Tok: tfbridge.MakeDataSource(mainPkg, osubUsageMod, "getComputedUsages")},

			"oci_queue_queue":  {Tok: tfbridge.MakeDataSource(mainPkg, queueMod, "getQueue")},
			"oci_queue_queues": {Tok: tfbridge.MakeDataSource(mainPkg, queueMod, "getQueues")},

			"oci_resourcemanager_stack":                         {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getStack")},
			"oci_resourcemanager_stack_tf_state":                {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getStackTfState")},
			"oci_resourcemanager_stacks":                        {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getStacks")},
			"oci_resourcemanager_private_endpoint":              {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getPrivateEndpoint")},
			"oci_resourcemanager_private_endpoints":             {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getPrivateEndpoints")},
			"oci_resourcemanager_private_endpoint_reachable_ip": {Tok: tfbridge.MakeDataSource(mainPkg, resourceManagerMod, "getPrivateEndpointReachableIp")},

			"oci_sch_service_connector":  {Tok: tfbridge.MakeDataSource(mainPkg, schMod, "getServiceConnector")},
			"oci_sch_service_connectors": {Tok: tfbridge.MakeDataSource(mainPkg, schMod, "getServiceConnectors")},

			"oci_secrets_secretbundle":          {Tok: tfbridge.MakeDataSource(mainPkg, secretsMod, "getSecretbundle")},
			"oci_secrets_secretbundle_versions": {Tok: tfbridge.MakeDataSource(mainPkg, secretsMod, "getSecretbundleVersions")},

			"oci_service_catalog_private_application":          {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getPrivateApplication")},
			"oci_service_catalog_private_application_package":  {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getPrivateApplicationPackage")},
			"oci_service_catalog_private_application_packages": {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getPrivateApplicationPackages")},
			"oci_service_catalog_private_applications":         {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getPrivateApplications")},
			"oci_service_catalog_service_catalog":              {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getServiceCatalog")},
			"oci_service_catalog_service_catalog_association":  {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getServiceCatalogAssociation")},
			"oci_service_catalog_service_catalog_associations": {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getServiceCatalogAssociations")},
			"oci_service_catalog_service_catalogs":             {Tok: tfbridge.MakeDataSource(mainPkg, serviceCatalogMod, "getServiceCatalogs")},

			"oci_service_manager_proxy_service_environment":  {Tok: tfbridge.MakeDataSource(mainPkg, serviceManagerProxyMod, "getServiceEnvironment")},
			"oci_service_manager_proxy_service_environments": {Tok: tfbridge.MakeDataSource(mainPkg, serviceManagerProxyMod, "getServiceEnvironments")},

			"oci_service_mesh_access_policies":              {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getAccessPolicies")},
			"oci_service_mesh_access_policy":                {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getAccessPolicy")},
			"oci_service_mesh_ingress_gateway":              {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getIngressGateway")},
			"oci_service_mesh_ingress_gateways":             {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getIngressGateways")},
			"oci_service_mesh_ingress_gateway_route_table":  {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getIngressGatewayRouteTable")},
			"oci_service_mesh_ingress_gateway_route_tables": {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getIngressGatewayRouteTables")},
			"oci_service_mesh_mesh":                         {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getMesh")},
			"oci_service_mesh_meshes":                       {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getMeshes")},
			"oci_service_mesh_proxy_detail":                 {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getProxyDetail")},
			"oci_service_mesh_virtual_deployment":           {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualDeployment")},
			"oci_service_mesh_virtual_deployments":          {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualDeployments")},
			"oci_service_mesh_virtual_service":              {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualService")},
			"oci_service_mesh_virtual_services":             {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualServices")},
			"oci_service_mesh_virtual_service_route_table":  {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualServiceRouteTable")},
			"oci_service_mesh_virtual_service_route_tables": {Tok: tfbridge.MakeDataSource(mainPkg, serviceMeshMod, "getVirtualServiceRouteTables")},

			"oci_stack_monitoring_discovery_job":      {Tok: tfbridge.MakeDataSource(mainPkg, stackMonitoringMod, "getDiscoveryJob")},
			"oci_stack_monitoring_discovery_job_logs": {Tok: tfbridge.MakeDataSource(mainPkg, stackMonitoringMod, "getDiscoveryJobLogs")},
			"oci_stack_monitoring_discovery_jobs":     {Tok: tfbridge.MakeDataSource(mainPkg, stackMonitoringMod, "getDiscoveryJobs")},
			"oci_stack_monitoring_monitored_resource": {Tok: tfbridge.MakeDataSource(mainPkg, stackMonitoringMod, "getMonitoredResource")},

			"oci_usage_proxy_subscription_product":          {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionProduct")},
			"oci_usage_proxy_subscription_products":         {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionProducts")},
			"oci_usage_proxy_subscription_redeemable_user":  {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionRedeemableUser")},
			"oci_usage_proxy_subscription_redeemable_users": {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionRedeemableUsers")},
			"oci_usage_proxy_subscription_redemption":       {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionRedemption")},
			"oci_usage_proxy_subscription_redemptions":      {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionRedemptions")},
			"oci_usage_proxy_subscription_reward":           {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionReward")},
			"oci_usage_proxy_subscription_rewards":          {Tok: tfbridge.MakeDataSource(mainPkg, usageProxyMod, "getSubscriptionRewards")},

			"oci_vn_monitoring_path_analyzer_test":  {Tok: tfbridge.MakeDataSource(mainPkg, vnMonitoringMod, "GetPathAnalyzerTest")},
			"oci_vn_monitoring_path_analyzer_tests": {Tok: tfbridge.MakeDataSource(mainPkg, vnMonitoringMod, "GetPathAnalyzerTests")},

			"oci_visual_builder_vb_instance":              {Tok: tfbridge.MakeDataSource(mainPkg, visualBuilderMod, "getVbInstance")},
			"oci_visual_builder_vb_instance_applications": {Tok: tfbridge.MakeDataSource(mainPkg, visualBuilderMod, "getVbInstanceApplications")},
			"oci_visual_builder_vb_instances":             {Tok: tfbridge.MakeDataSource(mainPkg, visualBuilderMod, "getVbInstances")},

			"oci_vulnerability_scanning_container_scan_recipe":   {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getContainerScanRecipe")},
			"oci_vulnerability_scanning_container_scan_recipes":  {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getContainerScanRecipes")},
			"oci_vulnerability_scanning_container_scan_target":   {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getContainerScanTarget")},
			"oci_vulnerability_scanning_container_scan_targets":  {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getContainerScanTargets")},
			"oci_vulnerability_scanning_host_scan_recipe":        {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getHostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_recipes":       {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getHostScanRecipes")},
			"oci_vulnerability_scanning_host_scan_target":        {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getHostScanTarget")},
			"oci_vulnerability_scanning_host_scan_targets":       {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getHostScanTargets")},
			"oci_vulnerability_scanning_host_scan_target_errors": {Tok: tfbridge.MakeDataSource(mainPkg, vulnerabilityScanningMod, "getHostScanTargetErrors")},

			"oci_waa_web_app_acceleration":          {Tok: tfbridge.MakeDataSource(mainPkg, waaMod, "getAppAcceleration")},
			"oci_waa_web_app_accelerations":         {Tok: tfbridge.MakeDataSource(mainPkg, waaMod, "getAppAccelerations")},
			"oci_waa_web_app_acceleration_policy":   {Tok: tfbridge.MakeDataSource(mainPkg, waaMod, "getAppAccelerationPolicy")},
			"oci_waa_web_app_acceleration_policies": {Tok: tfbridge.MakeDataSource(mainPkg, waaMod, "getAppAccelerationPolicies")},

			"oci_waas_address_list":            {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getAddressList")},
			"oci_waas_address_lists":           {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getAddressLists")},
			"oci_waas_certificate":             {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getCertificate")},
			"oci_waas_certificates":            {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getCertificates")},
			"oci_waas_custom_protection_rule":  {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getCustomProtectionRule")},
			"oci_waas_custom_protection_rules": {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getCustomProtectionRules")},
			"oci_waas_edge_subnets":            {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getEdgeSubnets")},
			"oci_waas_http_redirect":           {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getHttpRedirect")},
			"oci_waas_http_redirects":          {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getHttpRedirects")},
			"oci_waas_protection_rule":         {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getProtectionRule")},
			"oci_waas_protection_rules":        {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getProtectionRules")},
			"oci_waas_waas_policies":           {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getWaasPolicies")},
			"oci_waas_waas_policy":             {Tok: tfbridge.MakeDataSource(mainPkg, waasMod, "getWaasPolicy")},

			"oci_waf_network_address_list":             {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getNetworkAddressList")},
			"oci_waf_network_address_lists":            {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getNetworkAddressLists")},
			"oci_waf_protection_capabilities":          {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getProtectionCapabilities")},
			"oci_waf_protection_capability_group_tags": {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getProtectionCapabilityGroupTags")},
			"oci_waf_web_app_firewall":                 {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getWebAppFirewall")},
			"oci_waf_web_app_firewall_policies":        {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getWebAppFirewallPolicies")},
			"oci_waf_web_app_firewall_policy":          {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getWebAppFirewallPolicy")},
			"oci_waf_web_app_firewalls":                {Tok: tfbridge.MakeDataSource(mainPkg, wafMod, "getFirewalls")},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			// List any npm dependencies and their versions

			DevDependencies: map[string]string{
				"@types/node": "^10.0.0", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			// See the documentation for tfbridge.OverlayInfo for how to lay out this
			// section, or refer to the AWS provider. Delete this section if there are
			// no overlay files.
			// Overlay: &tfbridge.OverlayInfo{},
			RespectSchemaVersion: true,
		},
		Python: (func() *tfbridge.PythonInfo {
			i := &tfbridge.PythonInfo{
				RespectSchemaVersion: true,
			}
			i.PyProject.Enabled = true
			return i
		})(),

		Golang: &tfbridge.GolangInfo{
			ImportBasePath: filepath.Join(
				fmt.Sprintf("github.com/pulumi/pulumi-%[1]s/sdk/", mainPkg),
				tfbridge.GetModuleMajorVersion(version.Version),
				"go",
				mainPkg,
			),
			GenerateResourceContainerTypes: true,
			RespectSchemaVersion:           true,
		},
		CSharp: &tfbridge.CSharpInfo{
			RespectSchemaVersion: true,
			PackageReferences: map[string]string{
				"Pulumi": "3.*",
			},
		}, MetadataInfo: tfbridge.NewProviderMetadata(metadata),
	}

	prov.MustComputeTokens(tokens.MappedModules("oci_", "", mappedMods, tokens.MakeStandard(mainPkg)))

	// These are not preset upstream
	resourcesMissingDocs := []string{
		"oci_bds_bds_instance_os_patch_action",
		"oci_core_default_dhcp_options",
		"oci_core_default_route_table",
		"oci_core_default_security_list",
		"oci_core_virtual_network",
		"oci_data_safe_add_sdm_columns",
		"oci_data_safe_database_security_config_management",
		"oci_data_safe_mask_data",
		"oci_data_safe_masking_policies_apply_difference_to_masking_columns",
		"oci_data_safe_security_policy_deployment_management",
		"oci_data_safe_security_policy_management",
		"oci_data_safe_sensitive_data_models_apply_discovery_job_results",
		"oci_data_safe_sql_firewall_policy_management",
		"oci_database_autonomous_container_database_dataguard_role_change",
		"oci_database_exadata_infrastructure_storage",
		"oci_datascience_model_artifact_export",
		"oci_datascience_model_artifact_import",
		"oci_integration_oracle_managed_custom_endpoint",
		"oci_integration_private_endpoint_outbound_connection",
		"oci_objectstorage_namespace_metadata",
		"oci_objectstorage_private_endpoint",
	}
	for _, tk := range resourcesMissingDocs {
		r, ok := prov.Resources[tk]
		contract.Assertf(ok, "Expected resource %s", tk)
		r.Docs = &tfbridge.DocInfo{AllowMissing: true}
	}

	datasourcesMissingDocs := []string{
		"oci_bds_auto_scaling_configurations",
		"oci_containerengine_migrate_to_native_vcn_status",
		"oci_core_listing_resource_version",
		"oci_core_listing_resource_versions",
		"oci_core_shape",
		"oci_core_virtual_networks",
		"oci_data_safe_security_assessment_finding",
		"oci_data_safe_target_database_role",
		"oci_network_load_balancer_backend_set_health",
		"oci_objectstorage_namespace_metadata",
		"oci_objectstorage_private_endpoint",
		"oci_objectstorage_private_endpoint_summaries",
		"oci_vault_secret_version_sdk_v2",
	}
	for _, tk := range datasourcesMissingDocs {
		d, ok := prov.DataSources[tk]
		contract.Assertf(ok, "Expected datasource %s", tk)
		d.Docs = &tfbridge.DocInfo{AllowMissing: true}
	}

	prov.MustApplyAutoAliases()
	prov.SetAutonaming(255, "-")

	return prov
}

//go:embed cmd/pulumi-resource-oci/bridge-metadata.json
var metadata []byte

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ApiGateway.DeploymentArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentState;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecification;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Deployment resource in Oracle Cloud Infrastructure API Gateway service.
 * 
 * Creates a new deployment.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.ApiGateway.Deployment;
 * import com.pulumi.oci.ApiGateway.DeploymentArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationLoggingPoliciesArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationLoggingPoliciesAccessLogArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationLoggingPoliciesExecutionLogArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesAuthenticationArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesCorsArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesMutualTlsArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesRateLimitingArgs;
 * import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesUsagePlansArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testDeployment = new Deployment(&#34;testDeployment&#34;, DeploymentArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .gatewayId(oci_apigateway_gateway.test_gateway().id())
 *             .pathPrefix(var_.deployment_path_prefix())
 *             .specification(DeploymentSpecificationArgs.builder()
 *                 .loggingPolicies(DeploymentSpecificationLoggingPoliciesArgs.builder()
 *                     .accessLog(DeploymentSpecificationLoggingPoliciesAccessLogArgs.builder()
 *                         .isEnabled(var_.deployment_specification_logging_policies_access_log_is_enabled())
 *                         .build())
 *                     .executionLog(DeploymentSpecificationLoggingPoliciesExecutionLogArgs.builder()
 *                         .isEnabled(var_.deployment_specification_logging_policies_execution_log_is_enabled())
 *                         .logLevel(var_.deployment_specification_logging_policies_execution_log_log_level())
 *                         .build())
 *                     .build())
 *                 .requestPolicies(DeploymentSpecificationRequestPoliciesArgs.builder()
 *                     .authentication(DeploymentSpecificationRequestPoliciesAuthenticationArgs.builder()
 *                         .type(var_.deployment_specification_request_policies_authentication_type())
 *                         .audiences(var_.deployment_specification_request_policies_authentication_audiences())
 *                         .functionId(oci_functions_function.test_function().id())
 *                         .isAnonymousAccessAllowed(var_.deployment_specification_request_policies_authentication_is_anonymous_access_allowed())
 *                         .issuers(var_.deployment_specification_request_policies_authentication_issuers())
 *                         .maxClockSkewInSeconds(var_.deployment_specification_request_policies_authentication_max_clock_skew_in_seconds())
 *                         .publicKeys(DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysArgs.builder()
 *                             .type(var_.deployment_specification_request_policies_authentication_public_keys_type())
 *                             .isSslVerifyDisabled(var_.deployment_specification_request_policies_authentication_public_keys_is_ssl_verify_disabled())
 *                             .keys(DeploymentSpecificationRequestPoliciesAuthenticationPublicKeysKeyArgs.builder()
 *                                 .format(var_.deployment_specification_request_policies_authentication_public_keys_keys_format())
 *                                 .alg(var_.deployment_specification_request_policies_authentication_public_keys_keys_alg())
 *                                 .e(var_.deployment_specification_request_policies_authentication_public_keys_keys_e())
 *                                 .key(var_.deployment_specification_request_policies_authentication_public_keys_keys_key())
 *                                 .keyOps(var_.deployment_specification_request_policies_authentication_public_keys_keys_key_ops())
 *                                 .kid(var_.deployment_specification_request_policies_authentication_public_keys_keys_kid())
 *                                 .kty(var_.deployment_specification_request_policies_authentication_public_keys_keys_kty())
 *                                 .n(var_.deployment_specification_request_policies_authentication_public_keys_keys_n())
 *                                 .use(var_.deployment_specification_request_policies_authentication_public_keys_keys_use())
 *                                 .build())
 *                             .maxCacheDurationInHours(var_.deployment_specification_request_policies_authentication_public_keys_max_cache_duration_in_hours())
 *                             .uri(var_.deployment_specification_request_policies_authentication_public_keys_uri())
 *                             .build())
 *                         .tokenAuthScheme(var_.deployment_specification_request_policies_authentication_token_auth_scheme())
 *                         .tokenHeader(var_.deployment_specification_request_policies_authentication_token_header())
 *                         .tokenQueryParam(var_.deployment_specification_request_policies_authentication_token_query_param())
 *                         .verifyClaims(DeploymentSpecificationRequestPoliciesAuthenticationVerifyClaimArgs.builder()
 *                             .isRequired(var_.deployment_specification_request_policies_authentication_verify_claims_is_required())
 *                             .key(var_.deployment_specification_request_policies_authentication_verify_claims_key())
 *                             .values(var_.deployment_specification_request_policies_authentication_verify_claims_values())
 *                             .build())
 *                         .build())
 *                     .cors(DeploymentSpecificationRequestPoliciesCorsArgs.builder()
 *                         .allowedOrigins(var_.deployment_specification_request_policies_cors_allowed_origins())
 *                         .allowedHeaders(var_.deployment_specification_request_policies_cors_allowed_headers())
 *                         .allowedMethods(var_.deployment_specification_request_policies_cors_allowed_methods())
 *                         .exposedHeaders(var_.deployment_specification_request_policies_cors_exposed_headers())
 *                         .isAllowCredentialsEnabled(var_.deployment_specification_request_policies_cors_is_allow_credentials_enabled())
 *                         .maxAgeInSeconds(var_.deployment_specification_request_policies_cors_max_age_in_seconds())
 *                         .build())
 *                     .mutualTls(DeploymentSpecificationRequestPoliciesMutualTlsArgs.builder()
 *                         .allowedSans(var_.deployment_specification_request_policies_mutual_tls_allowed_sans())
 *                         .isVerifiedCertificateRequired(var_.deployment_specification_request_policies_mutual_tls_is_verified_certificate_required())
 *                         .build())
 *                     .rateLimiting(DeploymentSpecificationRequestPoliciesRateLimitingArgs.builder()
 *                         .rateInRequestsPerSecond(var_.deployment_specification_request_policies_rate_limiting_rate_in_requests_per_second())
 *                         .rateKey(var_.deployment_specification_request_policies_rate_limiting_rate_key())
 *                         .build())
 *                     .usagePlans(DeploymentSpecificationRequestPoliciesUsagePlansArgs.builder()
 *                         .tokenLocations(var_.deployment_specification_request_policies_usage_plans_token_locations())
 *                         .build())
 *                     .build())
 *                 .routes(DeploymentSpecificationRouteArgs.builder()
 *                     .backend(DeploymentSpecificationRouteBackendArgs.builder()
 *                         .type(var_.deployment_specification_routes_backend_type())
 *                         .body(var_.deployment_specification_routes_backend_body())
 *                         .connectTimeoutInSeconds(var_.deployment_specification_routes_backend_connect_timeout_in_seconds())
 *                         .functionId(oci_functions_function.test_function().id())
 *                         .headers(DeploymentSpecificationRouteBackendHeaderArgs.builder()
 *                             .name(var_.deployment_specification_routes_backend_headers_name())
 *                             .value(var_.deployment_specification_routes_backend_headers_value())
 *                             .build())
 *                         .isSslVerifyDisabled(var_.deployment_specification_routes_backend_is_ssl_verify_disabled())
 *                         .readTimeoutInSeconds(var_.deployment_specification_routes_backend_read_timeout_in_seconds())
 *                         .sendTimeoutInSeconds(var_.deployment_specification_routes_backend_send_timeout_in_seconds())
 *                         .status(var_.deployment_specification_routes_backend_status())
 *                         .url(var_.deployment_specification_routes_backend_url())
 *                         .build())
 *                     .path(var_.deployment_specification_routes_path())
 *                     .loggingPolicies(DeploymentSpecificationRouteLoggingPoliciesArgs.builder()
 *                         .accessLog(DeploymentSpecificationRouteLoggingPoliciesAccessLogArgs.builder()
 *                             .isEnabled(var_.deployment_specification_routes_logging_policies_access_log_is_enabled())
 *                             .build())
 *                         .executionLog(DeploymentSpecificationRouteLoggingPoliciesExecutionLogArgs.builder()
 *                             .isEnabled(var_.deployment_specification_routes_logging_policies_execution_log_is_enabled())
 *                             .logLevel(var_.deployment_specification_routes_logging_policies_execution_log_log_level())
 *                             .build())
 *                         .build())
 *                     .methods(var_.deployment_specification_routes_methods())
 *                     .requestPolicies(DeploymentSpecificationRouteRequestPoliciesArgs.builder()
 *                         .authorization(DeploymentSpecificationRouteRequestPoliciesAuthorizationArgs.builder()
 *                             .allowedScopes(var_.deployment_specification_routes_request_policies_authorization_allowed_scope())
 *                             .type(var_.deployment_specification_routes_request_policies_authorization_type())
 *                             .build())
 *                         .bodyValidation(DeploymentSpecificationRouteRequestPoliciesBodyValidationArgs.builder()
 *                             .contents(DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs.builder()
 *                                 .mediaType(var_.deployment_specification_routes_request_policies_body_validation_content_media_type())
 *                                 .validationType(var_.deployment_specification_routes_request_policies_body_validation_content_validation_type())
 *                                 .build())
 *                             .required(var_.deployment_specification_routes_request_policies_body_validation_required())
 *                             .validationMode(var_.deployment_specification_routes_request_policies_body_validation_validation_mode())
 *                             .build())
 *                         .cors(DeploymentSpecificationRouteRequestPoliciesCorsArgs.builder()
 *                             .allowedOrigins(var_.deployment_specification_routes_request_policies_cors_allowed_origins())
 *                             .allowedHeaders(var_.deployment_specification_routes_request_policies_cors_allowed_headers())
 *                             .allowedMethods(var_.deployment_specification_routes_request_policies_cors_allowed_methods())
 *                             .exposedHeaders(var_.deployment_specification_routes_request_policies_cors_exposed_headers())
 *                             .isAllowCredentialsEnabled(var_.deployment_specification_routes_request_policies_cors_is_allow_credentials_enabled())
 *                             .maxAgeInSeconds(var_.deployment_specification_routes_request_policies_cors_max_age_in_seconds())
 *                             .build())
 *                         .headerTransformations(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsArgs.builder()
 *                             .filterHeaders(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_request_policies_header_transformations_filter_headers_items_name())
 *                                     .build())
 *                                 .type(var_.deployment_specification_routes_request_policies_header_transformations_filter_headers_type())
 *                                 .build())
 *                             .renameHeaders(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs.builder()
 *                                     .from(var_.deployment_specification_routes_request_policies_header_transformations_rename_headers_items_from())
 *                                     .to(var_.deployment_specification_routes_request_policies_header_transformations_rename_headers_items_to())
 *                                     .build())
 *                                 .build())
 *                             .setHeaders(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsSetHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsSetHeadersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_request_policies_header_transformations_set_headers_items_name())
 *                                     .values(var_.deployment_specification_routes_request_policies_header_transformations_set_headers_items_values())
 *                                     .ifExists(var_.deployment_specification_routes_request_policies_header_transformations_set_headers_items_if_exists())
 *                                     .build())
 *                                 .build())
 *                             .build())
 *                         .headerValidations(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsArgs.builder()
 *                             .headers(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs.builder()
 *                                 .name(var_.deployment_specification_routes_request_policies_header_validations_headers_name())
 *                                 .required(var_.deployment_specification_routes_request_policies_header_validations_headers_required())
 *                                 .build())
 *                             .validationMode(var_.deployment_specification_routes_request_policies_header_validations_validation_mode())
 *                             .build())
 *                         .queryParameterTransformations(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsArgs.builder()
 *                             .filterQueryParameters(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_request_policies_query_parameter_transformations_filter_query_parameters_items_name())
 *                                     .build())
 *                                 .type(var_.deployment_specification_routes_request_policies_query_parameter_transformations_filter_query_parameters_type())
 *                                 .build())
 *                             .renameQueryParameters(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItemArgs.builder()
 *                                     .from(var_.deployment_specification_routes_request_policies_query_parameter_transformations_rename_query_parameters_items_from())
 *                                     .to(var_.deployment_specification_routes_request_policies_query_parameter_transformations_rename_query_parameters_items_to())
 *                                     .build())
 *                                 .build())
 *                             .setQueryParameters(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsSetQueryParametersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_request_policies_query_parameter_transformations_set_query_parameters_items_name())
 *                                     .values(var_.deployment_specification_routes_request_policies_query_parameter_transformations_set_query_parameters_items_values())
 *                                     .ifExists(var_.deployment_specification_routes_request_policies_query_parameter_transformations_set_query_parameters_items_if_exists())
 *                                     .build())
 *                                 .build())
 *                             .build())
 *                         .queryParameterValidations(DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsArgs.builder()
 *                             .parameters(DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameterArgs.builder()
 *                                 .name(var_.deployment_specification_routes_request_policies_query_parameter_validations_parameters_name())
 *                                 .required(var_.deployment_specification_routes_request_policies_query_parameter_validations_parameters_required())
 *                                 .build())
 *                             .validationMode(var_.deployment_specification_routes_request_policies_query_parameter_validations_validation_mode())
 *                             .build())
 *                         .responseCacheLookup(DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupArgs.builder()
 *                             .type(var_.deployment_specification_routes_request_policies_response_cache_lookup_type())
 *                             .cacheKeyAdditions(var_.deployment_specification_routes_request_policies_response_cache_lookup_cache_key_additions())
 *                             .isEnabled(var_.deployment_specification_routes_request_policies_response_cache_lookup_is_enabled())
 *                             .isPrivateCachingEnabled(var_.deployment_specification_routes_request_policies_response_cache_lookup_is_private_caching_enabled())
 *                             .build())
 *                         .build())
 *                     .responsePolicies(DeploymentSpecificationRouteResponsePoliciesArgs.builder()
 *                         .headerTransformations(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs.builder()
 *                             .filterHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_response_policies_header_transformations_filter_headers_items_name())
 *                                     .build())
 *                                 .type(var_.deployment_specification_routes_response_policies_header_transformations_filter_headers_type())
 *                                 .build())
 *                             .renameHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs.builder()
 *                                     .from(var_.deployment_specification_routes_response_policies_header_transformations_rename_headers_items_from())
 *                                     .to(var_.deployment_specification_routes_response_policies_header_transformations_rename_headers_items_to())
 *                                     .build())
 *                                 .build())
 *                             .setHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs.builder()
 *                                 .items(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersItemArgs.builder()
 *                                     .name(var_.deployment_specification_routes_response_policies_header_transformations_set_headers_items_name())
 *                                     .values(var_.deployment_specification_routes_response_policies_header_transformations_set_headers_items_values())
 *                                     .ifExists(var_.deployment_specification_routes_response_policies_header_transformations_set_headers_items_if_exists())
 *                                     .build())
 *                                 .build())
 *                             .build())
 *                         .responseCacheStore(DeploymentSpecificationRouteResponsePoliciesResponseCacheStoreArgs.builder()
 *                             .timeToLiveInSeconds(var_.deployment_specification_routes_response_policies_response_cache_store_time_to_live_in_seconds())
 *                             .type(var_.deployment_specification_routes_response_policies_response_cache_store_type())
 *                             .build())
 *                         .build())
 *                     .build())
 *                 .build())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .displayName(var_.deployment_display_name())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Deployments can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:ApiGateway/deployment:Deployment test_deployment &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ApiGateway/deployment:Deployment")
public class Deployment extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The endpoint to access this deployment on the gateway.
     * 
     */
    @Export(name="endpoint", type=String.class, parameters={})
    private Output<String> endpoint;

    /**
     * @return The endpoint to access this deployment on the gateway.
     * 
     */
    public Output<String> endpoint() {
        return this.endpoint;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    @Export(name="gatewayId", type=String.class, parameters={})
    private Output<String> gatewayId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Output<String> gatewayId() {
        return this.gatewayId;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * A path on which to deploy all routes contained in the API deployment specification. For more information, see [Deploying an API on an API Gateway by Creating an API Deployment](https://docs.cloud.oracle.com/iaas/Content/APIGateway/Tasks/apigatewaycreatingdeployment.htm).
     * 
     */
    @Export(name="pathPrefix", type=String.class, parameters={})
    private Output<String> pathPrefix;

    /**
     * @return A path on which to deploy all routes contained in the API deployment specification. For more information, see [Deploying an API on an API Gateway by Creating an API Deployment](https://docs.cloud.oracle.com/iaas/Content/APIGateway/Tasks/apigatewaycreatingdeployment.htm).
     * 
     */
    public Output<String> pathPrefix() {
        return this.pathPrefix;
    }
    /**
     * (Updatable) The logical configuration of the API exposed by a deployment.
     * 
     */
    @Export(name="specification", type=DeploymentSpecification.class, parameters={})
    private Output<DeploymentSpecification> specification;

    /**
     * @return (Updatable) The logical configuration of the API exposed by a deployment.
     * 
     */
    public Output<DeploymentSpecification> specification() {
        return this.specification;
    }
    /**
     * The current state of the deployment.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the deployment.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Deployment(String name) {
        this(name, DeploymentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Deployment(String name, DeploymentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Deployment(String name, DeploymentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ApiGateway/deployment:Deployment", name, args == null ? DeploymentArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Deployment(String name, Output<String> id, @Nullable DeploymentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ApiGateway/deployment:Deployment", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static Deployment get(String name, Output<String> id, @Nullable DeploymentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Deployment(name, id, state, options);
    }
}
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

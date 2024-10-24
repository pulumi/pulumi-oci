// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ServiceMesh.IngressGatewayArgs;
import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayState;
import com.pulumi.oci.ServiceMesh.outputs.IngressGatewayAccessLogging;
import com.pulumi.oci.ServiceMesh.outputs.IngressGatewayHost;
import com.pulumi.oci.ServiceMesh.outputs.IngressGatewayMtls;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Ingress Gateway resource in Oracle Cloud Infrastructure Service Mesh service.
 * 
 * Creates a new IngressGateway.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.ServiceMesh.IngressGateway;
 * import com.pulumi.oci.ServiceMesh.IngressGatewayArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayHostArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayAccessLoggingArgs;
 * import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayMtlsArgs;
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
 *         var testIngressGateway = new IngressGateway("testIngressGateway", IngressGatewayArgs.builder()
 *             .compartmentId(compartmentId)
 *             .hosts(IngressGatewayHostArgs.builder()
 *                 .listeners(IngressGatewayHostListenerArgs.builder()
 *                     .port(ingressGatewayHostsListenersPort)
 *                     .protocol(ingressGatewayHostsListenersProtocol)
 *                     .tls(IngressGatewayHostListenerTlsArgs.builder()
 *                         .mode(ingressGatewayHostsListenersTlsMode)
 *                         .clientValidation(IngressGatewayHostListenerTlsClientValidationArgs.builder()
 *                             .subjectAlternateNames(ingressGatewayHostsListenersTlsClientValidationSubjectAlternateNames)
 *                             .trustedCaBundle(IngressGatewayHostListenerTlsClientValidationTrustedCaBundleArgs.builder()
 *                                 .type(ingressGatewayHostsListenersTlsClientValidationTrustedCaBundleType)
 *                                 .caBundleId(testCaBundle.id())
 *                                 .secretName(testSecret.name())
 *                                 .build())
 *                             .build())
 *                         .serverCertificate(IngressGatewayHostListenerTlsServerCertificateArgs.builder()
 *                             .type(ingressGatewayHostsListenersTlsServerCertificateType)
 *                             .certificateId(testCertificate.id())
 *                             .secretName(testSecret.name())
 *                             .build())
 *                         .build())
 *                     .build())
 *                 .name(ingressGatewayHostsName)
 *                 .hostnames(ingressGatewayHostsHostnames)
 *                 .build())
 *             .meshId(testMesh.id())
 *             .name(ingressGatewayName)
 *             .accessLogging(IngressGatewayAccessLoggingArgs.builder()
 *                 .isEnabled(ingressGatewayAccessLoggingIsEnabled)
 *                 .build())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(ingressGatewayDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .mtls(IngressGatewayMtlsArgs.builder()
 *                 .maximumValidity(ingressGatewayMtlsMaximumValidity)
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * IngressGateways can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:ServiceMesh/ingressGateway:IngressGateway test_ingress_gateway &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ServiceMesh/ingressGateway:IngressGateway")
public class IngressGateway extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    @Export(name="accessLogging", refs={IngressGatewayAccessLogging.class}, tree="[0]")
    private Output<IngressGatewayAccessLogging> accessLogging;

    /**
     * @return (Updatable) This configuration determines if logging is enabled and where the logs will be output.
     * 
     */
    public Output<IngressGatewayAccessLogging> accessLogging() {
        return this.accessLogging;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) An array of hostnames and their listener configuration that this gateway will bind to.
     * 
     */
    @Export(name="hosts", refs={List.class,IngressGatewayHost.class}, tree="[0,1]")
    private Output<List<IngressGatewayHost>> hosts;

    /**
     * @return (Updatable) An array of hostnames and their listener configuration that this gateway will bind to.
     * 
     */
    public Output<List<IngressGatewayHost>> hosts() {
        return this.hosts;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The OCID of the service mesh in which this ingress gateway is created.
     * 
     */
    @Export(name="meshId", refs={String.class}, tree="[0]")
    private Output<String> meshId;

    /**
     * @return The OCID of the service mesh in which this ingress gateway is created.
     * 
     */
    public Output<String> meshId() {
        return this.meshId;
    }
    /**
     * (Updatable) Mutual TLS settings used when sending requests to virtual services within the mesh.
     * 
     */
    @Export(name="mtls", refs={IngressGatewayMtls.class}, tree="[0]")
    private Output<IngressGatewayMtls> mtls;

    /**
     * @return (Updatable) Mutual TLS settings used when sending requests to virtual services within the mesh.
     * 
     */
    public Output<IngressGatewayMtls> mtls() {
        return this.mtls;
    }
    /**
     * A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The current state of the Resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time when this resource was created in an RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time when this resource was updated in an RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public IngressGateway(java.lang.String name) {
        this(name, IngressGatewayArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public IngressGateway(java.lang.String name, IngressGatewayArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public IngressGateway(java.lang.String name, IngressGatewayArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceMesh/ingressGateway:IngressGateway", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private IngressGateway(java.lang.String name, Output<java.lang.String> id, @Nullable IngressGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ServiceMesh/ingressGateway:IngressGateway", name, state, makeResourceOptions(options, id), false);
    }

    private static IngressGatewayArgs makeArgs(IngressGatewayArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? IngressGatewayArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static IngressGateway get(java.lang.String name, Output<java.lang.String> id, @Nullable IngressGatewayState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new IngressGateway(name, id, state, options);
    }
}

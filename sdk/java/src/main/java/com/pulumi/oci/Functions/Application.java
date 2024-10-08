// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Functions.ApplicationArgs;
import com.pulumi.oci.Functions.inputs.ApplicationState;
import com.pulumi.oci.Functions.outputs.ApplicationImagePolicyConfig;
import com.pulumi.oci.Functions.outputs.ApplicationTraceConfig;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
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
 * import com.pulumi.oci.Functions.Application;
 * import com.pulumi.oci.Functions.ApplicationArgs;
 * import com.pulumi.oci.Functions.inputs.ApplicationImagePolicyConfigArgs;
 * import com.pulumi.oci.Functions.inputs.ApplicationTraceConfigArgs;
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
 *         var testApplication = new Application("testApplication", ApplicationArgs.builder()
 *             .compartmentId(compartmentId)
 *             .displayName(applicationDisplayName)
 *             .subnetIds(applicationSubnetIds)
 *             .config(applicationConfig)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .networkSecurityGroupIds(applicationNetworkSecurityGroupIds)
 *             .imagePolicyConfig(ApplicationImagePolicyConfigArgs.builder()
 *                 .isPolicyEnabled(applicationImagePolicyConfigIsPolicyEnabled)
 *                 .keyDetails(ApplicationImagePolicyConfigKeyDetailArgs.builder()
 *                     .kmsKeyId(testKey.id())
 *                     .build())
 *                 .build())
 *             .shape(applicationShape)
 *             .syslogUrl(applicationSyslogUrl)
 *             .traceConfig(ApplicationTraceConfigArgs.builder()
 *                 .domainId(testDomain.id())
 *                 .isEnabled(applicationTraceConfigIsEnabled)
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
 * Applications can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Functions/application:Application test_application &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Functions/application:Application")
public class Application extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment to create the application within.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment to create the application within.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Application configuration. These values are passed on to the function as environment variables, functions may override application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     * The maximum size for all configuration keys and values is limited to 4KB. This is measured as the sum of octets necessary to represent each key and value in UTF-8.
     * 
     */
    @Export(name="config", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> config;

    /**
     * @return (Updatable) Application configuration. These values are passed on to the function as environment variables, functions may override application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     * The maximum size for all configuration keys and values is limited to 4KB. This is measured as the sum of octets necessary to represent each key and value in UTF-8.
     * 
     */
    public Output<Map<String,String>> config() {
        return this.config;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * The display name of the application. The display name must be unique within the compartment containing the application. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return The display name of the application. The display name must be unique within the compartment containing the application. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) Define the image signature verification policy for an application.
     * 
     */
    @Export(name="imagePolicyConfig", refs={ApplicationImagePolicyConfig.class}, tree="[0]")
    private Output<ApplicationImagePolicyConfig> imagePolicyConfig;

    /**
     * @return (Updatable) Define the image signature verification policy for an application.
     * 
     */
    public Output<ApplicationImagePolicyConfig> imagePolicyConfig() {
        return this.imagePolicyConfig;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the Network Security Groups to add the application to.
     * 
     */
    @Export(name="networkSecurityGroupIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> networkSecurityGroupIds;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the Network Security Groups to add the application to.
     * 
     */
    public Output<List<String>> networkSecurityGroupIds() {
        return this.networkSecurityGroupIds;
    }
    /**
     * Valid values are `GENERIC_X86`, `GENERIC_ARM` and `GENERIC_X86_ARM`. Default is `GENERIC_X86`. Setting this to `GENERIC_X86`, will run the functions in the application on X86 processor architecture. Setting this to `GENERIC_ARM`, will run the functions in the application on ARM processor architecture. When set to `GENERIC_X86_ARM`, functions in the application are run on either X86 or ARM processor architecture. Accepted values are: `GENERIC_X86`, `GENERIC_ARM`, `GENERIC_X86_ARM`
     * 
     */
    @Export(name="shape", refs={String.class}, tree="[0]")
    private Output<String> shape;

    /**
     * @return Valid values are `GENERIC_X86`, `GENERIC_ARM` and `GENERIC_X86_ARM`. Default is `GENERIC_X86`. Setting this to `GENERIC_X86`, will run the functions in the application on X86 processor architecture. Setting this to `GENERIC_ARM`, will run the functions in the application on ARM processor architecture. When set to `GENERIC_X86_ARM`, functions in the application are run on either X86 or ARM processor architecture. Accepted values are: `GENERIC_X86`, `GENERIC_ARM`, `GENERIC_X86_ARM`
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }
    /**
     * The current state of the application.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the application.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the subnets in which to run functions in the application.
     * 
     */
    @Export(name="subnetIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> subnetIds;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of the subnets in which to run functions in the application.
     * 
     */
    public Output<List<String>> subnetIds() {
        return this.subnetIds;
    }
    /**
     * (Updatable) A syslog URL to which to send all function logs. Supports tcp, udp, and tcp+tls. The syslog URL must be reachable from all of the subnets configured for the application. Note: If you enable the Oracle Cloud Infrastructure Logging service for this application, the syslogUrl value is ignored. Function logs are sent to the Oracle Cloud Infrastructure Logging service, and not to the syslog URL.  Example: `tcp://logserver.myserver:1234`
     * 
     */
    @Export(name="syslogUrl", refs={String.class}, tree="[0]")
    private Output<String> syslogUrl;

    /**
     * @return (Updatable) A syslog URL to which to send all function logs. Supports tcp, udp, and tcp+tls. The syslog URL must be reachable from all of the subnets configured for the application. Note: If you enable the Oracle Cloud Infrastructure Logging service for this application, the syslogUrl value is ignored. Function logs are sent to the Oracle Cloud Infrastructure Logging service, and not to the syslog URL.  Example: `tcp://logserver.myserver:1234`
     * 
     */
    public Output<String> syslogUrl() {
        return this.syslogUrl;
    }
    /**
     * The time the application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) Define the tracing configuration for an application.
     * 
     */
    @Export(name="traceConfig", refs={ApplicationTraceConfig.class}, tree="[0]")
    private Output<ApplicationTraceConfig> traceConfig;

    /**
     * @return (Updatable) Define the tracing configuration for an application.
     * 
     */
    public Output<ApplicationTraceConfig> traceConfig() {
        return this.traceConfig;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Application(java.lang.String name) {
        this(name, ApplicationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Application(java.lang.String name, ApplicationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Application(java.lang.String name, ApplicationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Functions/application:Application", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Application(java.lang.String name, Output<java.lang.String> id, @Nullable ApplicationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Functions/application:Application", name, state, makeResourceOptions(options, id), false);
    }

    private static ApplicationArgs makeArgs(ApplicationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ApplicationArgs.Empty : args;
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
    public static Application get(java.lang.String name, Output<java.lang.String> id, @Nullable ApplicationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Application(name, id, state, options);
    }
}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.ApplicationVipArgs;
import com.pulumi.oci.Database.inputs.ApplicationVipState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Application Vip resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates a new application virtual IP (VIP) address in the specified cloud VM cluster based on the request parameters you provide.
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
 * import com.pulumi.oci.Database.ApplicationVip;
 * import com.pulumi.oci.Database.ApplicationVipArgs;
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
 *         var testApplicationVip = new ApplicationVip("testApplicationVip", ApplicationVipArgs.builder()
 *             .cloudVmClusterId(testCloudVmCluster.id())
 *             .hostnameLabel(applicationVipHostnameLabel)
 *             .subnetId(testSubnet.id())
 *             .dbNodeId(testDbNode.id())
 *             .ipAddress(applicationVipIpAddress)
 *             .ipv6address(applicationVipIpv6address)
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
 * ApplicationVips can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Database/applicationVip:ApplicationVip test_application_vip &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/applicationVip:ApplicationVip")
public class ApplicationVip extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
     * 
     */
    @Export(name="cloudVmClusterId", refs={String.class}, tree="[0]")
    private Output<String> cloudVmClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
     * 
     */
    public Output<String> cloudVmClusterId() {
        return this.cloudVmClusterId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB node associated with the application virtual IP (VIP) address.
     * 
     */
    @Export(name="dbNodeId", refs={String.class}, tree="[0]")
    private Output<String> dbNodeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB node associated with the application virtual IP (VIP) address.
     * 
     */
    public Output<String> dbNodeId() {
        return this.dbNodeId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The hostname of the application virtual IP (VIP) address.
     * 
     */
    @Export(name="hostnameLabel", refs={String.class}, tree="[0]")
    private Output<String> hostnameLabel;

    /**
     * @return The hostname of the application virtual IP (VIP) address.
     * 
     */
    public Output<String> hostnameLabel() {
        return this.hostnameLabel;
    }
    /**
     * The application virtual IP (VIP) IPv4 address.
     * 
     */
    @Export(name="ipAddress", refs={String.class}, tree="[0]")
    private Output<String> ipAddress;

    /**
     * @return The application virtual IP (VIP) IPv4 address.
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }
    /**
     * The application virtual IP (VIP) IPv6 address.
     * 
     */
    @Export(name="ipv6address", refs={String.class}, tree="[0]")
    private Output<String> ipv6address;

    /**
     * @return The application virtual IP (VIP) IPv6 address.
     * 
     */
    public Output<String> ipv6address() {
        return this.ipv6address;
    }
    /**
     * Additional information about the current lifecycle state of the application virtual IP (VIP) address.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state of the application virtual IP (VIP) address.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The current lifecycle state of the application virtual IP (VIP) address.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current lifecycle state of the application virtual IP (VIP) address.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the application virtual IP (VIP) address.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="subnetId", refs={String.class}, tree="[0]")
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the application virtual IP (VIP) address.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * The date and time when the create operation for the application virtual IP (VIP) address completed.
     * 
     */
    @Export(name="timeAssigned", refs={String.class}, tree="[0]")
    private Output<String> timeAssigned;

    /**
     * @return The date and time when the create operation for the application virtual IP (VIP) address completed.
     * 
     */
    public Output<String> timeAssigned() {
        return this.timeAssigned;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ApplicationVip(java.lang.String name) {
        this(name, ApplicationVipArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ApplicationVip(java.lang.String name, ApplicationVipArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ApplicationVip(java.lang.String name, ApplicationVipArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/applicationVip:ApplicationVip", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ApplicationVip(java.lang.String name, Output<java.lang.String> id, @Nullable ApplicationVipState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/applicationVip:ApplicationVip", name, state, makeResourceOptions(options, id), false);
    }

    private static ApplicationVipArgs makeArgs(ApplicationVipArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ApplicationVipArgs.Empty : args;
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
    public static ApplicationVip get(java.lang.String name, Output<java.lang.String> id, @Nullable ApplicationVipState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ApplicationVip(name, id, state, options);
    }
}

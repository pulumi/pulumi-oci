// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.RouteTableAttachmentArgs;
import com.pulumi.oci.Core.inputs.RouteTableAttachmentState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the ability to associate a route table for a subnet in Oracle Cloud Infrastructure Core service.
 * 
 * Attaches the specified `route table` to the specified `subnet`.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Core.RouteTableAttachment;
 * import com.pulumi.oci.Core.RouteTableAttachmentArgs;
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
 *         var testRouteTableAttachment = new RouteTableAttachment(&#34;testRouteTableAttachment&#34;, RouteTableAttachmentArgs.builder()        
 *             .subnetId(oci_core_subnet.test_subnet().id())
 *             .routeTableId(oci_core_route_table.test_route_table().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Route Table Attachment can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Core/routeTableAttachment:RouteTableAttachment test_route_table_attachment &#34;{subnetId}/{routeTableId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/routeTableAttachment:RouteTableAttachment")
public class RouteTableAttachment extends com.pulumi.resources.CustomResource {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table.
     * 
     */
    @Export(name="routeTableId", type=String.class, parameters={})
    private Output<String> routeTableId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table.
     * 
     */
    public Output<String> routeTableId() {
        return this.routeTableId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    @Export(name="subnetId", type=String.class, parameters={})
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RouteTableAttachment(String name) {
        this(name, RouteTableAttachmentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RouteTableAttachment(String name, RouteTableAttachmentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RouteTableAttachment(String name, RouteTableAttachmentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/routeTableAttachment:RouteTableAttachment", name, args == null ? RouteTableAttachmentArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private RouteTableAttachment(String name, Output<String> id, @Nullable RouteTableAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/routeTableAttachment:RouteTableAttachment", name, state, makeResourceOptions(options, id));
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
    public static RouteTableAttachment get(String name, Output<String> id, @Nullable RouteTableAttachmentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RouteTableAttachment(name, id, state, options);
    }
}
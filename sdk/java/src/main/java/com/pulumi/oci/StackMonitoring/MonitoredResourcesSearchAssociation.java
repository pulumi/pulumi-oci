// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.StackMonitoring.MonitoredResourcesSearchAssociationArgs;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourcesSearchAssociationState;
import com.pulumi.oci.StackMonitoring.outputs.MonitoredResourcesSearchAssociationItem;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Monitored Resources Search Association resource in Oracle Cloud Infrastructure Stack Monitoring service.
 * 
 * Returns a list of monitored resource associations.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.StackMonitoring.MonitoredResourcesSearchAssociation;
 * import com.pulumi.oci.StackMonitoring.MonitoredResourcesSearchAssociationArgs;
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
 *         var testMonitoredResourcesSearchAssociation = new MonitoredResourcesSearchAssociation(&#34;testMonitoredResourcesSearchAssociation&#34;, MonitoredResourcesSearchAssociationArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .associationType(var_.monitored_resources_search_association_association_type())
 *             .destinationResourceId(oci_stack_monitoring_destination_resource.test_destination_resource().id())
 *             .destinationResourceName(var_.monitored_resources_search_association_destination_resource_name())
 *             .destinationResourceType(var_.monitored_resources_search_association_destination_resource_type())
 *             .sourceResourceId(oci_stack_monitoring_source_resource.test_source_resource().id())
 *             .sourceResourceName(var_.monitored_resources_search_association_source_resource_name())
 *             .sourceResourceType(var_.monitored_resources_search_association_source_resource_type())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * MonitoredResourcesSearchAssociations can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:StackMonitoring/monitoredResourcesSearchAssociation:MonitoredResourcesSearchAssociation test_monitored_resources_search_association &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:StackMonitoring/monitoredResourcesSearchAssociation:MonitoredResourcesSearchAssociation")
public class MonitoredResourcesSearchAssociation extends com.pulumi.resources.CustomResource {
    /**
     * Association type to be created between source and destination resources
     * 
     */
    @Export(name="associationType", type=String.class, parameters={})
    private Output</* @Nullable */ String> associationType;

    /**
     * @return Association type to be created between source and destination resources
     * 
     */
    public Output<Optional<String>> associationType() {
        return Codegen.optional(this.associationType);
    }
    /**
     * Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Export(name="destinationResourceId", type=String.class, parameters={})
    private Output</* @Nullable */ String> destinationResourceId;

    /**
     * @return Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Output<Optional<String>> destinationResourceId() {
        return Codegen.optional(this.destinationResourceId);
    }
    /**
     * Source Monitored Resource Name
     * 
     */
    @Export(name="destinationResourceName", type=String.class, parameters={})
    private Output</* @Nullable */ String> destinationResourceName;

    /**
     * @return Source Monitored Resource Name
     * 
     */
    public Output<Optional<String>> destinationResourceName() {
        return Codegen.optional(this.destinationResourceName);
    }
    /**
     * Source Monitored Resource Type
     * 
     */
    @Export(name="destinationResourceType", type=String.class, parameters={})
    private Output</* @Nullable */ String> destinationResourceType;

    /**
     * @return Source Monitored Resource Type
     * 
     */
    public Output<Optional<String>> destinationResourceType() {
        return Codegen.optional(this.destinationResourceType);
    }
    /**
     * List of Monitored Resource Associations.
     * 
     */
    @Export(name="items", type=List.class, parameters={MonitoredResourcesSearchAssociationItem.class})
    private Output<List<MonitoredResourcesSearchAssociationItem>> items;

    /**
     * @return List of Monitored Resource Associations.
     * 
     */
    public Output<List<MonitoredResourcesSearchAssociationItem>> items() {
        return this.items;
    }
    /**
     * Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Export(name="sourceResourceId", type=String.class, parameters={})
    private Output</* @Nullable */ String> sourceResourceId;

    /**
     * @return Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Output<Optional<String>> sourceResourceId() {
        return Codegen.optional(this.sourceResourceId);
    }
    /**
     * Source Monitored Resource Name
     * 
     */
    @Export(name="sourceResourceName", type=String.class, parameters={})
    private Output</* @Nullable */ String> sourceResourceName;

    /**
     * @return Source Monitored Resource Name
     * 
     */
    public Output<Optional<String>> sourceResourceName() {
        return Codegen.optional(this.sourceResourceName);
    }
    /**
     * Source Monitored Resource Type
     * 
     */
    @Export(name="sourceResourceType", type=String.class, parameters={})
    private Output</* @Nullable */ String> sourceResourceType;

    /**
     * @return Source Monitored Resource Type
     * 
     */
    public Output<Optional<String>> sourceResourceType() {
        return Codegen.optional(this.sourceResourceType);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MonitoredResourcesSearchAssociation(String name) {
        this(name, MonitoredResourcesSearchAssociationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MonitoredResourcesSearchAssociation(String name, MonitoredResourcesSearchAssociationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MonitoredResourcesSearchAssociation(String name, MonitoredResourcesSearchAssociationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoredResourcesSearchAssociation:MonitoredResourcesSearchAssociation", name, args == null ? MonitoredResourcesSearchAssociationArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private MonitoredResourcesSearchAssociation(String name, Output<String> id, @Nullable MonitoredResourcesSearchAssociationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:StackMonitoring/monitoredResourcesSearchAssociation:MonitoredResourcesSearchAssociation", name, state, makeResourceOptions(options, id));
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
    public static MonitoredResourcesSearchAssociation get(String name, Output<String> id, @Nullable MonitoredResourcesSearchAssociationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MonitoredResourcesSearchAssociation(name, id, state, options);
    }
}
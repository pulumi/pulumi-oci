// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Dns.ActionCreateZoneFromZoneFileArgs;
import com.pulumi.oci.Dns.inputs.ActionCreateZoneFromZoneFileState;
import com.pulumi.oci.Dns.outputs.ActionCreateZoneFromZoneFileDnssecConfig;
import com.pulumi.oci.Dns.outputs.ActionCreateZoneFromZoneFileExternalDownstream;
import com.pulumi.oci.Dns.outputs.ActionCreateZoneFromZoneFileExternalMaster;
import com.pulumi.oci.Dns.outputs.ActionCreateZoneFromZoneFileNameserver;
import com.pulumi.oci.Dns.outputs.ActionCreateZoneFromZoneFileZoneTransferServer;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Action Create Zone From Zone File resource in Oracle Cloud Infrastructure DNS service.
 * 
 * Creates a new zone from a zone file in the specified compartment. Not supported for private zones.
 * 
 * After the zone has been created, it should be further managed by importing it to an `oci.Dns.Zone` resource.
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
 * import com.pulumi.oci.Dns.ActionCreateZoneFromZoneFile;
 * import com.pulumi.oci.Dns.ActionCreateZoneFromZoneFileArgs;
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
 *         var testActionCreateZoneFromZoneFile = new ActionCreateZoneFromZoneFile("testActionCreateZoneFromZoneFile", ActionCreateZoneFromZoneFileArgs.builder()
 *             .createZoneFromZoneFileDetails(actionCreateZoneFromZoneFileCreateZoneFromZoneFileDetails)
 *             .compartmentId(compartmentId)
 *             .scope(actionCreateZoneFromZoneFileScope)
 *             .viewId(testView.id())
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
 * ActionCreateZoneFromZoneFile can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile test_action_create_zone_from_zone_file &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile")
public class ActionCreateZoneFromZoneFile extends com.pulumi.resources.CustomResource {
    /**
     * The OCID of the compartment the resource belongs to.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment the resource belongs to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The zone file contents.
     * 
     */
    @Export(name="createZoneFromZoneFileDetails", refs={String.class}, tree="[0]")
    private Output<String> createZoneFromZoneFileDetails;

    /**
     * @return The zone file contents.
     * 
     */
    public Output<String> createZoneFromZoneFileDetails() {
        return this.createZoneFromZoneFileDetails;
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
    @Export(name="dnssecConfigs", refs={List.class,ActionCreateZoneFromZoneFileDnssecConfig.class}, tree="[0,1]")
    private Output<List<ActionCreateZoneFromZoneFileDnssecConfig>> dnssecConfigs;

    public Output<List<ActionCreateZoneFromZoneFileDnssecConfig>> dnssecConfigs() {
        return this.dnssecConfigs;
    }
    @Export(name="dnssecState", refs={String.class}, tree="[0]")
    private Output<String> dnssecState;

    public Output<String> dnssecState() {
        return this.dnssecState;
    }
    /**
     * External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     * 
     */
    @Export(name="externalDownstreams", refs={List.class,ActionCreateZoneFromZoneFileExternalDownstream.class}, tree="[0,1]")
    private Output<List<ActionCreateZoneFromZoneFileExternalDownstream>> externalDownstreams;

    /**
     * @return External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     * 
     */
    public Output<List<ActionCreateZoneFromZoneFileExternalDownstream>> externalDownstreams() {
        return this.externalDownstreams;
    }
    /**
     * External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     * 
     */
    @Export(name="externalMasters", refs={List.class,ActionCreateZoneFromZoneFileExternalMaster.class}, tree="[0,1]")
    private Output<List<ActionCreateZoneFromZoneFileExternalMaster>> externalMasters;

    /**
     * @return External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     * 
     */
    public Output<List<ActionCreateZoneFromZoneFileExternalMaster>> externalMasters() {
        return this.externalMasters;
    }
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     * 
     */
    @Export(name="isProtected", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isProtected;

    /**
     * @return A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     * 
     */
    public Output<Boolean> isProtected() {
        return this.isProtected;
    }
    /**
     * The name of the zone.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name of the zone.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * The authoritative nameservers for the zone.
     * 
     */
    @Export(name="nameservers", refs={List.class,ActionCreateZoneFromZoneFileNameserver.class}, tree="[0,1]")
    private Output<List<ActionCreateZoneFromZoneFileNameserver>> nameservers;

    /**
     * @return The authoritative nameservers for the zone.
     * 
     */
    public Output<List<ActionCreateZoneFromZoneFileNameserver>> nameservers() {
        return this.nameservers;
    }
    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     * 
     */
    @Export(name="scope", refs={String.class}, tree="[0]")
    private Output<String> scope;

    /**
     * @return Specifies to operate only on resources that have a matching DNS scope.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }
    /**
     * The canonical absolute URL of the resource.
     * 
     */
    @Export(name="self", refs={String.class}, tree="[0]")
    private Output<String> self;

    /**
     * @return The canonical absolute URL of the resource.
     * 
     */
    public Output<String> self() {
        return this.self;
    }
    /**
     * The current serial of the zone. As seen in the zone&#39;s SOA record.
     * 
     */
    @Export(name="serial", refs={String.class}, tree="[0]")
    private Output<String> serial;

    /**
     * @return The current serial of the zone. As seen in the zone&#39;s SOA record.
     * 
     */
    public Output<String> serial() {
        return this.serial;
    }
    /**
     * The current state of the zone resource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the zone resource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created in &#34;YYYY-MM-ddThh:mm:ssZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone&#39;s SOA record is derived.
     * 
     */
    @Export(name="version", refs={String.class}, tree="[0]")
    private Output<String> version;

    /**
     * @return Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone&#39;s SOA record is derived.
     * 
     */
    public Output<String> version() {
        return this.version;
    }
    /**
     * The OCID of the view the resource is associated with.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="viewId", refs={String.class}, tree="[0]")
    private Output<String> viewId;

    /**
     * @return The OCID of the view the resource is associated with.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> viewId() {
        return this.viewId;
    }
    /**
     * The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     * 
     */
    @Export(name="zoneTransferServers", refs={List.class,ActionCreateZoneFromZoneFileZoneTransferServer.class}, tree="[0,1]")
    private Output<List<ActionCreateZoneFromZoneFileZoneTransferServer>> zoneTransferServers;

    /**
     * @return The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     * 
     */
    public Output<List<ActionCreateZoneFromZoneFileZoneTransferServer>> zoneTransferServers() {
        return this.zoneTransferServers;
    }
    /**
     * The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     * 
     */
    @Export(name="zoneType", refs={String.class}, tree="[0]")
    private Output<String> zoneType;

    /**
     * @return The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     * 
     */
    public Output<String> zoneType() {
        return this.zoneType;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ActionCreateZoneFromZoneFile(java.lang.String name) {
        this(name, ActionCreateZoneFromZoneFileArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ActionCreateZoneFromZoneFile(java.lang.String name, ActionCreateZoneFromZoneFileArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ActionCreateZoneFromZoneFile(java.lang.String name, ActionCreateZoneFromZoneFileArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ActionCreateZoneFromZoneFile(java.lang.String name, Output<java.lang.String> id, @Nullable ActionCreateZoneFromZoneFileState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile", name, state, makeResourceOptions(options, id), false);
    }

    private static ActionCreateZoneFromZoneFileArgs makeArgs(ActionCreateZoneFromZoneFileArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ActionCreateZoneFromZoneFileArgs.Empty : args;
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
    public static ActionCreateZoneFromZoneFile get(java.lang.String name, Output<java.lang.String> id, @Nullable ActionCreateZoneFromZoneFileState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ActionCreateZoneFromZoneFile(name, id, state, options);
    }
}

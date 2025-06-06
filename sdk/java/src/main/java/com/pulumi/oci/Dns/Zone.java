// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Dns.ZoneArgs;
import com.pulumi.oci.Dns.inputs.ZoneState;
import com.pulumi.oci.Dns.outputs.ZoneDnssecConfig;
import com.pulumi.oci.Dns.outputs.ZoneExternalDownstream;
import com.pulumi.oci.Dns.outputs.ZoneExternalMaster;
import com.pulumi.oci.Dns.outputs.ZoneNameserver;
import com.pulumi.oci.Dns.outputs.ZoneZoneTransferServer;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Zone resource in Oracle Cloud Infrastructure DNS service.
 * 
 * Creates a new zone in the specified compartment.
 * 
 * Private zones must have a zone type of `PRIMARY`. Creating a private zone at or under `oraclevcn.com`
 * within the default protected view of a VCN-dedicated resolver is not permitted.
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
 * import com.pulumi.oci.Dns.Zone;
 * import com.pulumi.oci.Dns.ZoneArgs;
 * import com.pulumi.oci.Dns.inputs.ZoneExternalDownstreamArgs;
 * import com.pulumi.oci.Dns.inputs.ZoneExternalMasterArgs;
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
 *         var testZone = new Zone("testZone", ZoneArgs.builder()
 *             .compartmentId(compartmentId)
 *             .name(zoneName)
 *             .zoneType(zoneZoneType)
 *             .definedTags(zoneDefinedTags)
 *             .dnssecState(zoneDnssecState)
 *             .externalDownstreams(ZoneExternalDownstreamArgs.builder()
 *                 .address(zoneExternalDownstreamsAddress)
 *                 .port(zoneExternalDownstreamsPort)
 *                 .tsigKeyId(testTsigKey.id())
 *                 .build())
 *             .externalMasters(ZoneExternalMasterArgs.builder()
 *                 .address(zoneExternalMastersAddress)
 *                 .port(zoneExternalMastersPort)
 *                 .tsigKeyId(testTsigKey.id())
 *                 .build())
 *             .freeformTags(zoneFreeformTags)
 *             .scope(zoneScope)
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
 * Zones can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Dns/zone:Zone test_zone &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Dns/zone:Zone")
public class Zone extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment containing the zone.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the zone.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Operations&#34;: {&#34;CostCenter&#34;: &#34;42&#34;}}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Operations&#34;: {&#34;CostCenter&#34;: &#34;42&#34;}}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * DNSSEC configuration data.
     * 
     */
    @Export(name="dnssecConfigs", refs={List.class,ZoneDnssecConfig.class}, tree="[0,1]")
    private Output<List<ZoneDnssecConfig>> dnssecConfigs;

    /**
     * @return DNSSEC configuration data.
     * 
     */
    public Output<List<ZoneDnssecConfig>> dnssecConfigs() {
        return this.dnssecConfigs;
    }
    /**
     * (Updatable) The state of DNSSEC on the zone.
     * 
     * For DNSSEC to function, every parent zone in the DNS tree up to the top-level domain (or an independent trust anchor) must also have DNSSEC correctly set up. After enabling DNSSEC, you must add a DS record to the zone&#39;s parent zone containing the `KskDnssecKeyVersion` data. You can find the DS data in the `dsData` attribute of the `KskDnssecKeyVersion`. Then, use the `PromoteZoneDnssecKeyVersion` operation to promote the `KskDnssecKeyVersion`.
     * 
     * New `KskDnssecKeyVersion`s are generated annually, a week before the existing `KskDnssecKeyVersion`&#39;s expiration. To rollover a `KskDnssecKeyVersion`, you must replace the parent zone&#39;s DS record containing the old `KskDnssecKeyVersion` data with the data from the new `KskDnssecKeyVersion`.
     * 
     * To remove the old DS record without causing service disruption, wait until the old DS record&#39;s TTL has expired, and the new DS record has propagated. After the DS replacement has been completed, then the `PromoteZoneDnssecKeyVersion` operation must be called.
     * 
     * Metrics are emitted in the `oci_dns` namespace daily for each `KskDnssecKeyVersion` indicating how many days are left until expiration. We recommend that you set up alarms and notifications for KskDnssecKeyVersion expiration so that the necessary parent zone updates can be made and the `PromoteZoneDnssecKeyVersion` operation can be called.
     * 
     * Enabling DNSSEC results in additional records in DNS responses which increases their size and can cause higher response latency.
     * 
     * For more information, see [DNSSEC](https://docs.cloud.oracle.com/iaas/Content/DNS/Concepts/dnssec.htm).
     * 
     */
    @Export(name="dnssecState", refs={String.class}, tree="[0]")
    private Output<String> dnssecState;

    /**
     * @return (Updatable) The state of DNSSEC on the zone.
     * 
     * For DNSSEC to function, every parent zone in the DNS tree up to the top-level domain (or an independent trust anchor) must also have DNSSEC correctly set up. After enabling DNSSEC, you must add a DS record to the zone&#39;s parent zone containing the `KskDnssecKeyVersion` data. You can find the DS data in the `dsData` attribute of the `KskDnssecKeyVersion`. Then, use the `PromoteZoneDnssecKeyVersion` operation to promote the `KskDnssecKeyVersion`.
     * 
     * New `KskDnssecKeyVersion`s are generated annually, a week before the existing `KskDnssecKeyVersion`&#39;s expiration. To rollover a `KskDnssecKeyVersion`, you must replace the parent zone&#39;s DS record containing the old `KskDnssecKeyVersion` data with the data from the new `KskDnssecKeyVersion`.
     * 
     * To remove the old DS record without causing service disruption, wait until the old DS record&#39;s TTL has expired, and the new DS record has propagated. After the DS replacement has been completed, then the `PromoteZoneDnssecKeyVersion` operation must be called.
     * 
     * Metrics are emitted in the `oci_dns` namespace daily for each `KskDnssecKeyVersion` indicating how many days are left until expiration. We recommend that you set up alarms and notifications for KskDnssecKeyVersion expiration so that the necessary parent zone updates can be made and the `PromoteZoneDnssecKeyVersion` operation can be called.
     * 
     * Enabling DNSSEC results in additional records in DNS responses which increases their size and can cause higher response latency.
     * 
     * For more information, see [DNSSEC](https://docs.cloud.oracle.com/iaas/Content/DNS/Concepts/dnssec.htm).
     * 
     */
    public Output<String> dnssecState() {
        return this.dnssecState;
    }
    /**
     * (Updatable) External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     * 
     */
    @Export(name="externalDownstreams", refs={List.class,ZoneExternalDownstream.class}, tree="[0,1]")
    private Output<List<ZoneExternalDownstream>> externalDownstreams;

    /**
     * @return (Updatable) External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
     * 
     */
    public Output<List<ZoneExternalDownstream>> externalDownstreams() {
        return this.externalDownstreams;
    }
    /**
     * (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     * 
     */
    @Export(name="externalMasters", refs={List.class,ZoneExternalMaster.class}, tree="[0,1]")
    private Output<List<ZoneExternalMaster>> externalMasters;

    /**
     * @return (Updatable) External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
     * 
     */
    public Output<List<ZoneExternalMaster>> externalMasters() {
        return this.externalMasters;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     * **Example:** `{&#34;Department&#34;: &#34;Finance&#34;}`
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
    @Export(name="nameservers", refs={List.class,ZoneNameserver.class}, tree="[0,1]")
    private Output<List<ZoneNameserver>> nameservers;

    /**
     * @return The authoritative nameservers for the zone.
     * 
     */
    public Output<List<ZoneNameserver>> nameservers() {
        return this.nameservers;
    }
    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     * This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
     * 
     */
    @Export(name="scope", refs={String.class}, tree="[0]")
    private Output<String> scope;

    /**
     * @return Specifies to operate only on resources that have a matching DNS scope.
     * This value will be null for zones in the global DNS and `PRIVATE` when creating a private zone.
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
    @Export(name="serial", refs={Integer.class}, tree="[0]")
    private Output<Integer> serial;

    /**
     * @return The current serial of the zone. As seen in the zone&#39;s SOA record.
     * 
     */
    public Output<Integer> serial() {
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
     * The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
     * 
     */
    @Export(name="viewId", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> viewId;

    /**
     * @return The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
     * 
     */
    public Output<Optional<String>> viewId() {
        return Codegen.optional(this.viewId);
    }
    /**
     * The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     * 
     */
    @Export(name="zoneTransferServers", refs={List.class,ZoneZoneTransferServer.class}, tree="[0,1]")
    private Output<List<ZoneZoneTransferServer>> zoneTransferServers;

    /**
     * @return The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
     * 
     */
    public Output<List<ZoneZoneTransferServer>> zoneTransferServers() {
        return this.zoneTransferServers;
    }
    /**
     * The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="zoneType", refs={String.class}, tree="[0]")
    private Output<String> zoneType;

    /**
     * @return The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> zoneType() {
        return this.zoneType;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Zone(java.lang.String name) {
        this(name, ZoneArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Zone(java.lang.String name, ZoneArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Zone(java.lang.String name, ZoneArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/zone:Zone", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Zone(java.lang.String name, Output<java.lang.String> id, @Nullable ZoneState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Dns/zone:Zone", name, state, makeResourceOptions(options, id), false);
    }

    private static ZoneArgs makeArgs(ZoneArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ZoneArgs.Empty : args;
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
    public static Zone get(java.lang.String name, Output<java.lang.String> id, @Nullable ZoneState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Zone(name, id, state, options);
    }
}

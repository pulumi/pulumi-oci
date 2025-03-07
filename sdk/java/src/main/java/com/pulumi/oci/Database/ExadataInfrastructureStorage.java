// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.ExadataInfrastructureStorageArgs;
import com.pulumi.oci.Database.inputs.ExadataInfrastructureStorageState;
import com.pulumi.oci.Database.outputs.ExadataInfrastructureStorageContact;
import com.pulumi.oci.Database.outputs.ExadataInfrastructureStorageMaintenanceWindow;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

@ResourceType(type="oci:Database/exadataInfrastructureStorage:ExadataInfrastructureStorage")
public class ExadataInfrastructureStorage extends com.pulumi.resources.CustomResource {
    @Export(name="activatedStorageCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> activatedStorageCount;

    public Output<Integer> activatedStorageCount() {
        return this.activatedStorageCount;
    }
    @Export(name="activationFile", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> activationFile;

    public Output<Optional<String>> activationFile() {
        return Codegen.optional(this.activationFile);
    }
    @Export(name="additionalStorageCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> additionalStorageCount;

    public Output<Integer> additionalStorageCount() {
        return this.additionalStorageCount;
    }
    @Export(name="adminNetworkCidr", refs={String.class}, tree="[0]")
    private Output<String> adminNetworkCidr;

    public Output<String> adminNetworkCidr() {
        return this.adminNetworkCidr;
    }
    @Export(name="cloudControlPlaneServer1", refs={String.class}, tree="[0]")
    private Output<String> cloudControlPlaneServer1;

    public Output<String> cloudControlPlaneServer1() {
        return this.cloudControlPlaneServer1;
    }
    @Export(name="cloudControlPlaneServer2", refs={String.class}, tree="[0]")
    private Output<String> cloudControlPlaneServer2;

    public Output<String> cloudControlPlaneServer2() {
        return this.cloudControlPlaneServer2;
    }
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    @Export(name="computeCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> computeCount;

    public Output<Integer> computeCount() {
        return this.computeCount;
    }
    @Export(name="contacts", refs={List.class,ExadataInfrastructureStorageContact.class}, tree="[0,1]")
    private Output</* @Nullable */ List<ExadataInfrastructureStorageContact>> contacts;

    public Output<Optional<List<ExadataInfrastructureStorageContact>>> contacts() {
        return Codegen.optional(this.contacts);
    }
    @Export(name="corporateProxy", refs={String.class}, tree="[0]")
    private Output<String> corporateProxy;

    public Output<String> corporateProxy() {
        return this.corporateProxy;
    }
    @Export(name="cpusEnabled", refs={Integer.class}, tree="[0]")
    private Output<Integer> cpusEnabled;

    public Output<Integer> cpusEnabled() {
        return this.cpusEnabled;
    }
    @Export(name="csiNumber", refs={String.class}, tree="[0]")
    private Output<String> csiNumber;

    public Output<String> csiNumber() {
        return this.csiNumber;
    }
    @Export(name="dataStorageSizeInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> dataStorageSizeInTbs;

    public Output<Double> dataStorageSizeInTbs() {
        return this.dataStorageSizeInTbs;
    }
    @Export(name="dbNodeStorageSizeInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> dbNodeStorageSizeInGbs;

    public Output<Integer> dbNodeStorageSizeInGbs() {
        return this.dbNodeStorageSizeInGbs;
    }
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="dnsServers", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> dnsServers;

    public Output<List<String>> dnsServers() {
        return this.dnsServers;
    }
    @Export(name="exadataInfrastructureId", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> exadataInfrastructureId;

    public Output<Optional<String>> exadataInfrastructureId() {
        return Codegen.optional(this.exadataInfrastructureId);
    }
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    @Export(name="gateway", refs={String.class}, tree="[0]")
    private Output<String> gateway;

    public Output<String> gateway() {
        return this.gateway;
    }
    @Export(name="infiniBandNetworkCidr", refs={String.class}, tree="[0]")
    private Output<String> infiniBandNetworkCidr;

    public Output<String> infiniBandNetworkCidr() {
        return this.infiniBandNetworkCidr;
    }
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    @Export(name="maintenanceSloStatus", refs={String.class}, tree="[0]")
    private Output<String> maintenanceSloStatus;

    public Output<String> maintenanceSloStatus() {
        return this.maintenanceSloStatus;
    }
    @Export(name="maintenanceWindow", refs={ExadataInfrastructureStorageMaintenanceWindow.class}, tree="[0]")
    private Output<ExadataInfrastructureStorageMaintenanceWindow> maintenanceWindow;

    public Output<ExadataInfrastructureStorageMaintenanceWindow> maintenanceWindow() {
        return this.maintenanceWindow;
    }
    @Export(name="maxCpuCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> maxCpuCount;

    public Output<Integer> maxCpuCount() {
        return this.maxCpuCount;
    }
    @Export(name="maxDataStorageInTbs", refs={Double.class}, tree="[0]")
    private Output<Double> maxDataStorageInTbs;

    public Output<Double> maxDataStorageInTbs() {
        return this.maxDataStorageInTbs;
    }
    @Export(name="maxDbNodeStorageInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> maxDbNodeStorageInGbs;

    public Output<Integer> maxDbNodeStorageInGbs() {
        return this.maxDbNodeStorageInGbs;
    }
    @Export(name="maxMemoryInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> maxMemoryInGbs;

    public Output<Integer> maxMemoryInGbs() {
        return this.maxMemoryInGbs;
    }
    @Export(name="memorySizeInGbs", refs={Integer.class}, tree="[0]")
    private Output<Integer> memorySizeInGbs;

    public Output<Integer> memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    @Export(name="netmask", refs={String.class}, tree="[0]")
    private Output<String> netmask;

    public Output<String> netmask() {
        return this.netmask;
    }
    @Export(name="ntpServers", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> ntpServers;

    public Output<List<String>> ntpServers() {
        return this.ntpServers;
    }
    @Export(name="shape", refs={String.class}, tree="[0]")
    private Output<String> shape;

    public Output<String> shape() {
        return this.shape;
    }
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    public Output<String> state() {
        return this.state;
    }
    @Export(name="storageCount", refs={Integer.class}, tree="[0]")
    private Output<Integer> storageCount;

    public Output<Integer> storageCount() {
        return this.storageCount;
    }
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    @Export(name="timeZone", refs={String.class}, tree="[0]")
    private Output<String> timeZone;

    public Output<String> timeZone() {
        return this.timeZone;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExadataInfrastructureStorage(java.lang.String name) {
        this(name, ExadataInfrastructureStorageArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExadataInfrastructureStorage(java.lang.String name, ExadataInfrastructureStorageArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExadataInfrastructureStorage(java.lang.String name, ExadataInfrastructureStorageArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/exadataInfrastructureStorage:ExadataInfrastructureStorage", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExadataInfrastructureStorage(java.lang.String name, Output<java.lang.String> id, @Nullable ExadataInfrastructureStorageState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/exadataInfrastructureStorage:ExadataInfrastructureStorage", name, state, makeResourceOptions(options, id), false);
    }

    private static ExadataInfrastructureStorageArgs makeArgs(ExadataInfrastructureStorageArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExadataInfrastructureStorageArgs.Empty : args;
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
    public static ExadataInfrastructureStorage get(java.lang.String name, Output<java.lang.String> id, @Nullable ExadataInfrastructureStorageState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExadataInfrastructureStorage(name, id, state, options);
    }
}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.ExadataInfrastructureStorageContactArgs;
import com.pulumi.oci.Database.inputs.ExadataInfrastructureStorageMaintenanceWindowArgs;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExadataInfrastructureStorageState extends com.pulumi.resources.ResourceArgs {

    public static final ExadataInfrastructureStorageState Empty = new ExadataInfrastructureStorageState();

    @Import(name="activatedStorageCount")
    private @Nullable Output<Integer> activatedStorageCount;

    public Optional<Output<Integer>> activatedStorageCount() {
        return Optional.ofNullable(this.activatedStorageCount);
    }

    @Import(name="activationFile")
    private @Nullable Output<String> activationFile;

    public Optional<Output<String>> activationFile() {
        return Optional.ofNullable(this.activationFile);
    }

    @Import(name="additionalStorageCount")
    private @Nullable Output<Integer> additionalStorageCount;

    public Optional<Output<Integer>> additionalStorageCount() {
        return Optional.ofNullable(this.additionalStorageCount);
    }

    @Import(name="adminNetworkCidr")
    private @Nullable Output<String> adminNetworkCidr;

    public Optional<Output<String>> adminNetworkCidr() {
        return Optional.ofNullable(this.adminNetworkCidr);
    }

    @Import(name="cloudControlPlaneServer1")
    private @Nullable Output<String> cloudControlPlaneServer1;

    public Optional<Output<String>> cloudControlPlaneServer1() {
        return Optional.ofNullable(this.cloudControlPlaneServer1);
    }

    @Import(name="cloudControlPlaneServer2")
    private @Nullable Output<String> cloudControlPlaneServer2;

    public Optional<Output<String>> cloudControlPlaneServer2() {
        return Optional.ofNullable(this.cloudControlPlaneServer2);
    }

    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="computeCount")
    private @Nullable Output<Integer> computeCount;

    public Optional<Output<Integer>> computeCount() {
        return Optional.ofNullable(this.computeCount);
    }

    @Import(name="contacts")
    private @Nullable Output<List<ExadataInfrastructureStorageContactArgs>> contacts;

    public Optional<Output<List<ExadataInfrastructureStorageContactArgs>>> contacts() {
        return Optional.ofNullable(this.contacts);
    }

    @Import(name="corporateProxy")
    private @Nullable Output<String> corporateProxy;

    public Optional<Output<String>> corporateProxy() {
        return Optional.ofNullable(this.corporateProxy);
    }

    @Import(name="cpusEnabled")
    private @Nullable Output<Integer> cpusEnabled;

    public Optional<Output<Integer>> cpusEnabled() {
        return Optional.ofNullable(this.cpusEnabled);
    }

    @Import(name="csiNumber")
    private @Nullable Output<String> csiNumber;

    public Optional<Output<String>> csiNumber() {
        return Optional.ofNullable(this.csiNumber);
    }

    @Import(name="dataStorageSizeInTbs")
    private @Nullable Output<Double> dataStorageSizeInTbs;

    public Optional<Output<Double>> dataStorageSizeInTbs() {
        return Optional.ofNullable(this.dataStorageSizeInTbs);
    }

    @Import(name="dbNodeStorageSizeInGbs")
    private @Nullable Output<Integer> dbNodeStorageSizeInGbs;

    public Optional<Output<Integer>> dbNodeStorageSizeInGbs() {
        return Optional.ofNullable(this.dbNodeStorageSizeInGbs);
    }

    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="dnsServers")
    private @Nullable Output<List<String>> dnsServers;

    public Optional<Output<List<String>>> dnsServers() {
        return Optional.ofNullable(this.dnsServers);
    }

    @Import(name="exadataInfrastructureId")
    private @Nullable Output<String> exadataInfrastructureId;

    public Optional<Output<String>> exadataInfrastructureId() {
        return Optional.ofNullable(this.exadataInfrastructureId);
    }

    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    @Import(name="gateway")
    private @Nullable Output<String> gateway;

    public Optional<Output<String>> gateway() {
        return Optional.ofNullable(this.gateway);
    }

    @Import(name="infiniBandNetworkCidr")
    private @Nullable Output<String> infiniBandNetworkCidr;

    public Optional<Output<String>> infiniBandNetworkCidr() {
        return Optional.ofNullable(this.infiniBandNetworkCidr);
    }

    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    @Import(name="maintenanceSloStatus")
    private @Nullable Output<String> maintenanceSloStatus;

    public Optional<Output<String>> maintenanceSloStatus() {
        return Optional.ofNullable(this.maintenanceSloStatus);
    }

    @Import(name="maintenanceWindow")
    private @Nullable Output<ExadataInfrastructureStorageMaintenanceWindowArgs> maintenanceWindow;

    public Optional<Output<ExadataInfrastructureStorageMaintenanceWindowArgs>> maintenanceWindow() {
        return Optional.ofNullable(this.maintenanceWindow);
    }

    @Import(name="maxCpuCount")
    private @Nullable Output<Integer> maxCpuCount;

    public Optional<Output<Integer>> maxCpuCount() {
        return Optional.ofNullable(this.maxCpuCount);
    }

    @Import(name="maxDataStorageInTbs")
    private @Nullable Output<Double> maxDataStorageInTbs;

    public Optional<Output<Double>> maxDataStorageInTbs() {
        return Optional.ofNullable(this.maxDataStorageInTbs);
    }

    @Import(name="maxDbNodeStorageInGbs")
    private @Nullable Output<Integer> maxDbNodeStorageInGbs;

    public Optional<Output<Integer>> maxDbNodeStorageInGbs() {
        return Optional.ofNullable(this.maxDbNodeStorageInGbs);
    }

    @Import(name="maxMemoryInGbs")
    private @Nullable Output<Integer> maxMemoryInGbs;

    public Optional<Output<Integer>> maxMemoryInGbs() {
        return Optional.ofNullable(this.maxMemoryInGbs);
    }

    @Import(name="memorySizeInGbs")
    private @Nullable Output<Integer> memorySizeInGbs;

    public Optional<Output<Integer>> memorySizeInGbs() {
        return Optional.ofNullable(this.memorySizeInGbs);
    }

    @Import(name="netmask")
    private @Nullable Output<String> netmask;

    public Optional<Output<String>> netmask() {
        return Optional.ofNullable(this.netmask);
    }

    @Import(name="ntpServers")
    private @Nullable Output<List<String>> ntpServers;

    public Optional<Output<List<String>>> ntpServers() {
        return Optional.ofNullable(this.ntpServers);
    }

    @Import(name="shape")
    private @Nullable Output<String> shape;

    public Optional<Output<String>> shape() {
        return Optional.ofNullable(this.shape);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="storageCount")
    private @Nullable Output<Integer> storageCount;

    public Optional<Output<Integer>> storageCount() {
        return Optional.ofNullable(this.storageCount);
    }

    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    @Import(name="timeZone")
    private @Nullable Output<String> timeZone;

    public Optional<Output<String>> timeZone() {
        return Optional.ofNullable(this.timeZone);
    }

    private ExadataInfrastructureStorageState() {}

    private ExadataInfrastructureStorageState(ExadataInfrastructureStorageState $) {
        this.activatedStorageCount = $.activatedStorageCount;
        this.activationFile = $.activationFile;
        this.additionalStorageCount = $.additionalStorageCount;
        this.adminNetworkCidr = $.adminNetworkCidr;
        this.cloudControlPlaneServer1 = $.cloudControlPlaneServer1;
        this.cloudControlPlaneServer2 = $.cloudControlPlaneServer2;
        this.compartmentId = $.compartmentId;
        this.computeCount = $.computeCount;
        this.contacts = $.contacts;
        this.corporateProxy = $.corporateProxy;
        this.cpusEnabled = $.cpusEnabled;
        this.csiNumber = $.csiNumber;
        this.dataStorageSizeInTbs = $.dataStorageSizeInTbs;
        this.dbNodeStorageSizeInGbs = $.dbNodeStorageSizeInGbs;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.dnsServers = $.dnsServers;
        this.exadataInfrastructureId = $.exadataInfrastructureId;
        this.freeformTags = $.freeformTags;
        this.gateway = $.gateway;
        this.infiniBandNetworkCidr = $.infiniBandNetworkCidr;
        this.lifecycleDetails = $.lifecycleDetails;
        this.maintenanceSloStatus = $.maintenanceSloStatus;
        this.maintenanceWindow = $.maintenanceWindow;
        this.maxCpuCount = $.maxCpuCount;
        this.maxDataStorageInTbs = $.maxDataStorageInTbs;
        this.maxDbNodeStorageInGbs = $.maxDbNodeStorageInGbs;
        this.maxMemoryInGbs = $.maxMemoryInGbs;
        this.memorySizeInGbs = $.memorySizeInGbs;
        this.netmask = $.netmask;
        this.ntpServers = $.ntpServers;
        this.shape = $.shape;
        this.state = $.state;
        this.storageCount = $.storageCount;
        this.timeCreated = $.timeCreated;
        this.timeZone = $.timeZone;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExadataInfrastructureStorageState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExadataInfrastructureStorageState $;

        public Builder() {
            $ = new ExadataInfrastructureStorageState();
        }

        public Builder(ExadataInfrastructureStorageState defaults) {
            $ = new ExadataInfrastructureStorageState(Objects.requireNonNull(defaults));
        }

        public Builder activatedStorageCount(@Nullable Output<Integer> activatedStorageCount) {
            $.activatedStorageCount = activatedStorageCount;
            return this;
        }

        public Builder activatedStorageCount(Integer activatedStorageCount) {
            return activatedStorageCount(Output.of(activatedStorageCount));
        }

        public Builder activationFile(@Nullable Output<String> activationFile) {
            $.activationFile = activationFile;
            return this;
        }

        public Builder activationFile(String activationFile) {
            return activationFile(Output.of(activationFile));
        }

        public Builder additionalStorageCount(@Nullable Output<Integer> additionalStorageCount) {
            $.additionalStorageCount = additionalStorageCount;
            return this;
        }

        public Builder additionalStorageCount(Integer additionalStorageCount) {
            return additionalStorageCount(Output.of(additionalStorageCount));
        }

        public Builder adminNetworkCidr(@Nullable Output<String> adminNetworkCidr) {
            $.adminNetworkCidr = adminNetworkCidr;
            return this;
        }

        public Builder adminNetworkCidr(String adminNetworkCidr) {
            return adminNetworkCidr(Output.of(adminNetworkCidr));
        }

        public Builder cloudControlPlaneServer1(@Nullable Output<String> cloudControlPlaneServer1) {
            $.cloudControlPlaneServer1 = cloudControlPlaneServer1;
            return this;
        }

        public Builder cloudControlPlaneServer1(String cloudControlPlaneServer1) {
            return cloudControlPlaneServer1(Output.of(cloudControlPlaneServer1));
        }

        public Builder cloudControlPlaneServer2(@Nullable Output<String> cloudControlPlaneServer2) {
            $.cloudControlPlaneServer2 = cloudControlPlaneServer2;
            return this;
        }

        public Builder cloudControlPlaneServer2(String cloudControlPlaneServer2) {
            return cloudControlPlaneServer2(Output.of(cloudControlPlaneServer2));
        }

        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder computeCount(@Nullable Output<Integer> computeCount) {
            $.computeCount = computeCount;
            return this;
        }

        public Builder computeCount(Integer computeCount) {
            return computeCount(Output.of(computeCount));
        }

        public Builder contacts(@Nullable Output<List<ExadataInfrastructureStorageContactArgs>> contacts) {
            $.contacts = contacts;
            return this;
        }

        public Builder contacts(List<ExadataInfrastructureStorageContactArgs> contacts) {
            return contacts(Output.of(contacts));
        }

        public Builder contacts(ExadataInfrastructureStorageContactArgs... contacts) {
            return contacts(List.of(contacts));
        }

        public Builder corporateProxy(@Nullable Output<String> corporateProxy) {
            $.corporateProxy = corporateProxy;
            return this;
        }

        public Builder corporateProxy(String corporateProxy) {
            return corporateProxy(Output.of(corporateProxy));
        }

        public Builder cpusEnabled(@Nullable Output<Integer> cpusEnabled) {
            $.cpusEnabled = cpusEnabled;
            return this;
        }

        public Builder cpusEnabled(Integer cpusEnabled) {
            return cpusEnabled(Output.of(cpusEnabled));
        }

        public Builder csiNumber(@Nullable Output<String> csiNumber) {
            $.csiNumber = csiNumber;
            return this;
        }

        public Builder csiNumber(String csiNumber) {
            return csiNumber(Output.of(csiNumber));
        }

        public Builder dataStorageSizeInTbs(@Nullable Output<Double> dataStorageSizeInTbs) {
            $.dataStorageSizeInTbs = dataStorageSizeInTbs;
            return this;
        }

        public Builder dataStorageSizeInTbs(Double dataStorageSizeInTbs) {
            return dataStorageSizeInTbs(Output.of(dataStorageSizeInTbs));
        }

        public Builder dbNodeStorageSizeInGbs(@Nullable Output<Integer> dbNodeStorageSizeInGbs) {
            $.dbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            return this;
        }

        public Builder dbNodeStorageSizeInGbs(Integer dbNodeStorageSizeInGbs) {
            return dbNodeStorageSizeInGbs(Output.of(dbNodeStorageSizeInGbs));
        }

        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder dnsServers(@Nullable Output<List<String>> dnsServers) {
            $.dnsServers = dnsServers;
            return this;
        }

        public Builder dnsServers(List<String> dnsServers) {
            return dnsServers(Output.of(dnsServers));
        }

        public Builder dnsServers(String... dnsServers) {
            return dnsServers(List.of(dnsServers));
        }

        public Builder exadataInfrastructureId(@Nullable Output<String> exadataInfrastructureId) {
            $.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }

        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            return exadataInfrastructureId(Output.of(exadataInfrastructureId));
        }

        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public Builder gateway(@Nullable Output<String> gateway) {
            $.gateway = gateway;
            return this;
        }

        public Builder gateway(String gateway) {
            return gateway(Output.of(gateway));
        }

        public Builder infiniBandNetworkCidr(@Nullable Output<String> infiniBandNetworkCidr) {
            $.infiniBandNetworkCidr = infiniBandNetworkCidr;
            return this;
        }

        public Builder infiniBandNetworkCidr(String infiniBandNetworkCidr) {
            return infiniBandNetworkCidr(Output.of(infiniBandNetworkCidr));
        }

        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        public Builder maintenanceSloStatus(@Nullable Output<String> maintenanceSloStatus) {
            $.maintenanceSloStatus = maintenanceSloStatus;
            return this;
        }

        public Builder maintenanceSloStatus(String maintenanceSloStatus) {
            return maintenanceSloStatus(Output.of(maintenanceSloStatus));
        }

        public Builder maintenanceWindow(@Nullable Output<ExadataInfrastructureStorageMaintenanceWindowArgs> maintenanceWindow) {
            $.maintenanceWindow = maintenanceWindow;
            return this;
        }

        public Builder maintenanceWindow(ExadataInfrastructureStorageMaintenanceWindowArgs maintenanceWindow) {
            return maintenanceWindow(Output.of(maintenanceWindow));
        }

        public Builder maxCpuCount(@Nullable Output<Integer> maxCpuCount) {
            $.maxCpuCount = maxCpuCount;
            return this;
        }

        public Builder maxCpuCount(Integer maxCpuCount) {
            return maxCpuCount(Output.of(maxCpuCount));
        }

        public Builder maxDataStorageInTbs(@Nullable Output<Double> maxDataStorageInTbs) {
            $.maxDataStorageInTbs = maxDataStorageInTbs;
            return this;
        }

        public Builder maxDataStorageInTbs(Double maxDataStorageInTbs) {
            return maxDataStorageInTbs(Output.of(maxDataStorageInTbs));
        }

        public Builder maxDbNodeStorageInGbs(@Nullable Output<Integer> maxDbNodeStorageInGbs) {
            $.maxDbNodeStorageInGbs = maxDbNodeStorageInGbs;
            return this;
        }

        public Builder maxDbNodeStorageInGbs(Integer maxDbNodeStorageInGbs) {
            return maxDbNodeStorageInGbs(Output.of(maxDbNodeStorageInGbs));
        }

        public Builder maxMemoryInGbs(@Nullable Output<Integer> maxMemoryInGbs) {
            $.maxMemoryInGbs = maxMemoryInGbs;
            return this;
        }

        public Builder maxMemoryInGbs(Integer maxMemoryInGbs) {
            return maxMemoryInGbs(Output.of(maxMemoryInGbs));
        }

        public Builder memorySizeInGbs(@Nullable Output<Integer> memorySizeInGbs) {
            $.memorySizeInGbs = memorySizeInGbs;
            return this;
        }

        public Builder memorySizeInGbs(Integer memorySizeInGbs) {
            return memorySizeInGbs(Output.of(memorySizeInGbs));
        }

        public Builder netmask(@Nullable Output<String> netmask) {
            $.netmask = netmask;
            return this;
        }

        public Builder netmask(String netmask) {
            return netmask(Output.of(netmask));
        }

        public Builder ntpServers(@Nullable Output<List<String>> ntpServers) {
            $.ntpServers = ntpServers;
            return this;
        }

        public Builder ntpServers(List<String> ntpServers) {
            return ntpServers(Output.of(ntpServers));
        }

        public Builder ntpServers(String... ntpServers) {
            return ntpServers(List.of(ntpServers));
        }

        public Builder shape(@Nullable Output<String> shape) {
            $.shape = shape;
            return this;
        }

        public Builder shape(String shape) {
            return shape(Output.of(shape));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder storageCount(@Nullable Output<Integer> storageCount) {
            $.storageCount = storageCount;
            return this;
        }

        public Builder storageCount(Integer storageCount) {
            return storageCount(Output.of(storageCount));
        }

        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public Builder timeZone(@Nullable Output<String> timeZone) {
            $.timeZone = timeZone;
            return this;
        }

        public Builder timeZone(String timeZone) {
            return timeZone(Output.of(timeZone));
        }

        public ExadataInfrastructureStorageState build() {
            return $;
        }
    }

}
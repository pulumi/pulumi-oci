// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalExadataInfrastructureStorageGridArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalExadataInfrastructureStorageGridArgs Empty = new ExternalExadataInfrastructureStorageGridArgs();

    /**
     * The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="additionalDetails")
    private @Nullable Output<Map<String,String>> additionalDetails;

    /**
     * @return The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> additionalDetails() {
        return Optional.ofNullable(this.additionalDetails);
    }

    /**
     * (Updatable) The name of the Exadata infrastructure.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The internal ID of the Exadata resource.
     * 
     */
    @Import(name="internalId")
    private @Nullable Output<String> internalId;

    /**
     * @return The internal ID of the Exadata resource.
     * 
     */
    public Optional<Output<String>> internalId() {
        return Optional.ofNullable(this.internalId);
    }

    /**
     * The details of the lifecycle state of the Exadata resource.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return The details of the lifecycle state of the Exadata resource.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The number of Exadata storage servers in the Exadata infrastructure.
     * 
     */
    @Import(name="serverCount")
    private @Nullable Output<Double> serverCount;

    /**
     * @return The number of Exadata storage servers in the Exadata infrastructure.
     * 
     */
    public Optional<Output<Double>> serverCount() {
        return Optional.ofNullable(this.serverCount);
    }

    /**
     * The current lifecycle state of the database resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the database resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The status of the Exadata resource.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The status of the Exadata resource.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * The timestamp of the creation of the Exadata resource.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The timestamp of the creation of the Exadata resource.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The timestamp of the last update of the Exadata resource.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The timestamp of the last update of the Exadata resource.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The version of the Exadata resource.
     * 
     */
    @Import(name="version")
    private @Nullable Output<String> version;

    /**
     * @return The version of the Exadata resource.
     * 
     */
    public Optional<Output<String>> version() {
        return Optional.ofNullable(this.version);
    }

    private ExternalExadataInfrastructureStorageGridArgs() {}

    private ExternalExadataInfrastructureStorageGridArgs(ExternalExadataInfrastructureStorageGridArgs $) {
        this.additionalDetails = $.additionalDetails;
        this.displayName = $.displayName;
        this.id = $.id;
        this.internalId = $.internalId;
        this.lifecycleDetails = $.lifecycleDetails;
        this.serverCount = $.serverCount;
        this.state = $.state;
        this.status = $.status;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalExadataInfrastructureStorageGridArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalExadataInfrastructureStorageGridArgs $;

        public Builder() {
            $ = new ExternalExadataInfrastructureStorageGridArgs();
        }

        public Builder(ExternalExadataInfrastructureStorageGridArgs defaults) {
            $ = new ExternalExadataInfrastructureStorageGridArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalDetails The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder additionalDetails(@Nullable Output<Map<String,String>> additionalDetails) {
            $.additionalDetails = additionalDetails;
            return this;
        }

        /**
         * @param additionalDetails The additional details of the resource defined in `{&#34;key&#34;: &#34;value&#34;}` format. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder additionalDetails(Map<String,String> additionalDetails) {
            return additionalDetails(Output.of(additionalDetails));
        }

        /**
         * @param displayName (Updatable) The name of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param internalId The internal ID of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder internalId(@Nullable Output<String> internalId) {
            $.internalId = internalId;
            return this;
        }

        /**
         * @param internalId The internal ID of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder internalId(String internalId) {
            return internalId(Output.of(internalId));
        }

        /**
         * @param lifecycleDetails The details of the lifecycle state of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails The details of the lifecycle state of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param serverCount The number of Exadata storage servers in the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder serverCount(@Nullable Output<Double> serverCount) {
            $.serverCount = serverCount;
            return this;
        }

        /**
         * @param serverCount The number of Exadata storage servers in the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder serverCount(Double serverCount) {
            return serverCount(Output.of(serverCount));
        }

        /**
         * @param state The current lifecycle state of the database resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the database resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status The status of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The status of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeCreated The timestamp of the creation of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The timestamp of the creation of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The timestamp of the last update of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The timestamp of the last update of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param version The version of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder version(@Nullable Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version The version of the Exadata resource.
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public ExternalExadataInfrastructureStorageGridArgs build() {
            return $;
        }
    }

}

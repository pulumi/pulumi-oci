// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmSynthetics.inputs.DedicatedVantagePointDvpStackDetailsArgs;
import com.pulumi.oci.ApmSynthetics.inputs.DedicatedVantagePointMonitorStatusCountMapArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DedicatedVantagePointState extends com.pulumi.resources.ResourceArgs {

    public static final DedicatedVantagePointState Empty = new DedicatedVantagePointState();

    /**
     * (Updatable) The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId")
    private @Nullable Output<String> apmDomainId;

    /**
     * @return (Updatable) The APM domain ID the request is intended for.
     * 
     */
    public Optional<Output<String>> apmDomainId() {
        return Optional.ofNullable(this.apmDomainId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
     * 
     */
    @Import(name="dvpStackDetails")
    private @Nullable Output<DedicatedVantagePointDvpStackDetailsArgs> dvpStackDetails;

    /**
     * @return (Updatable) Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
     * 
     */
    public Optional<Output<DedicatedVantagePointDvpStackDetailsArgs>> dvpStackDetails() {
        return Optional.ofNullable(this.dvpStackDetails);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    @Import(name="monitorStatusCountMaps")
    private @Nullable Output<List<DedicatedVantagePointMonitorStatusCountMapArgs>> monitorStatusCountMaps;

    /**
     * @return Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    public Optional<Output<List<DedicatedVantagePointMonitorStatusCountMapArgs>>> monitorStatusCountMaps() {
        return Optional.ofNullable(this.monitorStatusCountMaps);
    }

    /**
     * Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Name of the region.
     * 
     */
    @Import(name="region")
    private @Nullable Output<String> region;

    /**
     * @return (Updatable) Name of the region.
     * 
     */
    public Optional<Output<String>> region() {
        return Optional.ofNullable(this.region);
    }

    /**
     * (Updatable) Status of the dedicated vantage point.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return (Updatable) Status of the dedicated vantage point.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private DedicatedVantagePointState() {}

    private DedicatedVantagePointState(DedicatedVantagePointState $) {
        this.apmDomainId = $.apmDomainId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.dvpStackDetails = $.dvpStackDetails;
        this.freeformTags = $.freeformTags;
        this.monitorStatusCountMaps = $.monitorStatusCountMaps;
        this.name = $.name;
        this.region = $.region;
        this.status = $.status;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DedicatedVantagePointState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DedicatedVantagePointState $;

        public Builder() {
            $ = new DedicatedVantagePointState();
        }

        public Builder(DedicatedVantagePointState defaults) {
            $ = new DedicatedVantagePointState(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(@Nullable Output<String> apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            return apmDomainId(Output.of(apmDomainId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param dvpStackDetails (Updatable) Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackDetails(@Nullable Output<DedicatedVantagePointDvpStackDetailsArgs> dvpStackDetails) {
            $.dvpStackDetails = dvpStackDetails;
            return this;
        }

        /**
         * @param dvpStackDetails (Updatable) Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
         * 
         * @return builder
         * 
         */
        public Builder dvpStackDetails(DedicatedVantagePointDvpStackDetailsArgs dvpStackDetails) {
            return dvpStackDetails(Output.of(dvpStackDetails));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(@Nullable Output<List<DedicatedVantagePointMonitorStatusCountMapArgs>> monitorStatusCountMaps) {
            $.monitorStatusCountMaps = monitorStatusCountMaps;
            return this;
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(List<DedicatedVantagePointMonitorStatusCountMapArgs> monitorStatusCountMaps) {
            return monitorStatusCountMaps(Output.of(monitorStatusCountMaps));
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(DedicatedVantagePointMonitorStatusCountMapArgs... monitorStatusCountMaps) {
            return monitorStatusCountMaps(List.of(monitorStatusCountMaps));
        }

        /**
         * @param name Unique permanent name of the dedicated vantage point. This is the same as the displayName.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Unique permanent name of the dedicated vantage point. This is the same as the displayName.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param region (Updatable) Name of the region.
         * 
         * @return builder
         * 
         */
        public Builder region(@Nullable Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region (Updatable) Name of the region.
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param status (Updatable) Status of the dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status (Updatable) Status of the dedicated vantage point.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param timeCreated The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public DedicatedVantagePointState build() {
            return $;
        }
    }

}
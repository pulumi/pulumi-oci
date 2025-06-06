// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetAutonomousExadataInfrastructuresFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousExadataInfrastructuresArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousExadataInfrastructuresArgs Empty = new GetAutonomousExadataInfrastructuresArgs();

    /**
     * A filter to return only resources that match the given availability domain exactly.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return A filter to return only resources that match the given availability domain exactly.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAutonomousExadataInfrastructuresFilterArgs>> filters;

    public Optional<Output<List<GetAutonomousExadataInfrastructuresFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAutonomousExadataInfrastructuresArgs() {}

    private GetAutonomousExadataInfrastructuresArgs(GetAutonomousExadataInfrastructuresArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousExadataInfrastructuresArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousExadataInfrastructuresArgs $;

        public Builder() {
            $ = new GetAutonomousExadataInfrastructuresArgs();
        }

        public Builder(GetAutonomousExadataInfrastructuresArgs defaults) {
            $ = new GetAutonomousExadataInfrastructuresArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain A filter to return only resources that match the given availability domain exactly.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain A filter to return only resources that match the given availability domain exactly.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetAutonomousExadataInfrastructuresFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAutonomousExadataInfrastructuresFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAutonomousExadataInfrastructuresFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetAutonomousExadataInfrastructuresArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetAutonomousExadataInfrastructuresArgs", "compartmentId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetDbServersFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbServersArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbServersArgs Empty = new GetDbServersArgs();

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

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
     * 
     */
    @Import(name="exadataInfrastructureId", required=true)
    private Output<String> exadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
     * 
     */
    public Output<String> exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDbServersFilterArgs>> filters;

    public Optional<Output<List<GetDbServersFilterArgs>>> filters() {
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

    private GetDbServersArgs() {}

    private GetDbServersArgs(GetDbServersArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.exadataInfrastructureId = $.exadataInfrastructureId;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbServersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbServersArgs $;

        public Builder() {
            $ = new GetDbServersArgs();
        }

        public Builder(GetDbServersArgs defaults) {
            $ = new GetDbServersArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param exadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(Output<String> exadataInfrastructureId) {
            $.exadataInfrastructureId = exadataInfrastructureId;
            return this;
        }

        /**
         * @param exadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
         * 
         * @return builder
         * 
         */
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            return exadataInfrastructureId(Output.of(exadataInfrastructureId));
        }

        public Builder filters(@Nullable Output<List<GetDbServersFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDbServersFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDbServersFilterArgs... filters) {
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

        public GetDbServersArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDbServersArgs", "compartmentId");
            }
            if ($.exadataInfrastructureId == null) {
                throw new MissingRequiredPropertyException("GetDbServersArgs", "exadataInfrastructureId");
            }
            return $;
        }
    }

}

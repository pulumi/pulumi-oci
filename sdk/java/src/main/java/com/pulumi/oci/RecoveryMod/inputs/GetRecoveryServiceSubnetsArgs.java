// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.RecoveryMod.inputs.GetRecoveryServiceSubnetsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRecoveryServiceSubnetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRecoveryServiceSubnetsArgs Empty = new GetRecoveryServiceSubnetsArgs();

    /**
     * The compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire &#39;displayname&#39; given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire &#39;displayname&#39; given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetRecoveryServiceSubnetsFilterArgs>> filters;

    public Optional<Output<List<GetRecoveryServiceSubnetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The recovery service subnet OCID.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The recovery service subnet OCID.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private GetRecoveryServiceSubnetsArgs() {}

    private GetRecoveryServiceSubnetsArgs(GetRecoveryServiceSubnetsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.state = $.state;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRecoveryServiceSubnetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecoveryServiceSubnetsArgs $;

        public Builder() {
            $ = new GetRecoveryServiceSubnetsArgs();
        }

        public Builder(GetRecoveryServiceSubnetsArgs defaults) {
            $ = new GetRecoveryServiceSubnetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire &#39;displayname&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire &#39;displayname&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetRecoveryServiceSubnetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRecoveryServiceSubnetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRecoveryServiceSubnetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The recovery service subnet OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The recovery service subnet OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param state A filter to return only the resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only the resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public GetRecoveryServiceSubnetsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetRecoveryServiceSubnetsArgs", "compartmentId");
            }
            return $;
        }
    }

}

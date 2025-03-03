// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.RecoveryMod.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.RecoveryMod.inputs.GetRecoveryServiceSubnetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRecoveryServiceSubnetsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRecoveryServiceSubnetsPlainArgs Empty = new GetRecoveryServiceSubnetsPlainArgs();

    /**
     * The compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire &#39;displayname&#39; given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire &#39;displayname&#39; given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetRecoveryServiceSubnetsFilter> filters;

    public Optional<List<GetRecoveryServiceSubnetsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The recovery service subnet OCID.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return The recovery service subnet OCID.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     * 
     */
    @Import(name="vcnId")
    private @Nullable String vcnId;

    /**
     * @return The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
     * 
     */
    public Optional<String> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private GetRecoveryServiceSubnetsPlainArgs() {}

    private GetRecoveryServiceSubnetsPlainArgs(GetRecoveryServiceSubnetsPlainArgs $) {
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
    public static Builder builder(GetRecoveryServiceSubnetsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecoveryServiceSubnetsPlainArgs $;

        public Builder() {
            $ = new GetRecoveryServiceSubnetsPlainArgs();
        }

        public Builder(GetRecoveryServiceSubnetsPlainArgs defaults) {
            $ = new GetRecoveryServiceSubnetsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire &#39;displayname&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetRecoveryServiceSubnetsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRecoveryServiceSubnetsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The recovery service subnet OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param state A filter to return only the resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param vcnId The OCID of the virtual cloud network (VCN) associated with the recovery service subnet.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable String vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        public GetRecoveryServiceSubnetsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetRecoveryServiceSubnetsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}

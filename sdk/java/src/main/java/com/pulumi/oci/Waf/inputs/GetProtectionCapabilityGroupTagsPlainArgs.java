// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waf.inputs.GetProtectionCapabilityGroupTagsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProtectionCapabilityGroupTagsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProtectionCapabilityGroupTagsPlainArgs Empty = new GetProtectionCapabilityGroupTagsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetProtectionCapabilityGroupTagsFilter> filters;

    public Optional<List<GetProtectionCapabilityGroupTagsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the entire name given.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to return only resources that matches given type.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return A filter to return only resources that matches given type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetProtectionCapabilityGroupTagsPlainArgs() {}

    private GetProtectionCapabilityGroupTagsPlainArgs(GetProtectionCapabilityGroupTagsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProtectionCapabilityGroupTagsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProtectionCapabilityGroupTagsPlainArgs $;

        public Builder() {
            $ = new GetProtectionCapabilityGroupTagsPlainArgs();
        }

        public Builder(GetProtectionCapabilityGroupTagsPlainArgs defaults) {
            $ = new GetProtectionCapabilityGroupTagsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetProtectionCapabilityGroupTagsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetProtectionCapabilityGroupTagsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only resources that match the entire name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param type A filter to return only resources that matches given type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetProtectionCapabilityGroupTagsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetProtectionCapabilityGroupTagsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Functions.inputs.GetFusionEnvironmentFamiliesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFusionEnvironmentFamiliesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentFamiliesPlainArgs Empty = new GetFusionEnvironmentFamiliesPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetFusionEnvironmentFamiliesFilter> filters;

    public Optional<List<GetFusionEnvironmentFamiliesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The ID of the fusion environment family in which to list resources.
     * 
     */
    @Import(name="fusionEnvironmentFamilyId")
    private @Nullable String fusionEnvironmentFamilyId;

    /**
     * @return The ID of the fusion environment family in which to list resources.
     * 
     */
    public Optional<String> fusionEnvironmentFamilyId() {
        return Optional.ofNullable(this.fusionEnvironmentFamilyId);
    }

    /**
     * A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetFusionEnvironmentFamiliesPlainArgs() {}

    private GetFusionEnvironmentFamiliesPlainArgs(GetFusionEnvironmentFamiliesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.fusionEnvironmentFamilyId = $.fusionEnvironmentFamilyId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentFamiliesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentFamiliesPlainArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentFamiliesPlainArgs();
        }

        public Builder(GetFusionEnvironmentFamiliesPlainArgs defaults) {
            $ = new GetFusionEnvironmentFamiliesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetFusionEnvironmentFamiliesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetFusionEnvironmentFamiliesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param fusionEnvironmentFamilyId The ID of the fusion environment family in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentFamilyId(@Nullable String fusionEnvironmentFamilyId) {
            $.fusionEnvironmentFamilyId = fusionEnvironmentFamilyId;
            return this;
        }

        /**
         * @param state A filter that returns all resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetFusionEnvironmentFamiliesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}
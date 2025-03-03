// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetExecutionActionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetExecutionActionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExecutionActionsPlainArgs Empty = new GetExecutionActionsPlainArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A filter to return only resources that match the given execution wondow id.
     * 
     */
    @Import(name="executionWindowId")
    private @Nullable String executionWindowId;

    /**
     * @return A filter to return only resources that match the given execution wondow id.
     * 
     */
    public Optional<String> executionWindowId() {
        return Optional.ofNullable(this.executionWindowId);
    }

    @Import(name="filters")
    private @Nullable List<GetExecutionActionsFilter> filters;

    public Optional<List<GetExecutionActionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetExecutionActionsPlainArgs() {}

    private GetExecutionActionsPlainArgs(GetExecutionActionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.executionWindowId = $.executionWindowId;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExecutionActionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExecutionActionsPlainArgs $;

        public Builder() {
            $ = new GetExecutionActionsPlainArgs();
        }

        public Builder(GetExecutionActionsPlainArgs defaults) {
            $ = new GetExecutionActionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given. The match is not case sensitive.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param executionWindowId A filter to return only resources that match the given execution wondow id.
         * 
         * @return builder
         * 
         */
        public Builder executionWindowId(@Nullable String executionWindowId) {
            $.executionWindowId = executionWindowId;
            return this;
        }

        public Builder filters(@Nullable List<GetExecutionActionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetExecutionActionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state exactly.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetExecutionActionsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetExecutionActionsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}

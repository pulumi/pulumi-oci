// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetDbHomePatchesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbHomePatchesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbHomePatchesPlainArgs Empty = new GetDbHomePatchesPlainArgs();

    /**
     * The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbHomeId", required=true)
    private String dbHomeId;

    /**
     * @return The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String dbHomeId() {
        return this.dbHomeId;
    }

    @Import(name="filters")
    private @Nullable List<GetDbHomePatchesFilter> filters;

    public Optional<List<GetDbHomePatchesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDbHomePatchesPlainArgs() {}

    private GetDbHomePatchesPlainArgs(GetDbHomePatchesPlainArgs $) {
        this.dbHomeId = $.dbHomeId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbHomePatchesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbHomePatchesPlainArgs $;

        public Builder() {
            $ = new GetDbHomePatchesPlainArgs();
        }

        public Builder(GetDbHomePatchesPlainArgs defaults) {
            $ = new GetDbHomePatchesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbHomeId The Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbHomeId(String dbHomeId) {
            $.dbHomeId = dbHomeId;
            return this;
        }

        public Builder filters(@Nullable List<GetDbHomePatchesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDbHomePatchesFilter... filters) {
            return filters(List.of(filters));
        }

        public GetDbHomePatchesPlainArgs build() {
            if ($.dbHomeId == null) {
                throw new MissingRequiredPropertyException("GetDbHomePatchesPlainArgs", "dbHomeId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AnnouncementsService.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AnnouncementsService.inputs.GetServicesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetServicesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetServicesPlainArgs Empty = new GetServicesPlainArgs();

    /**
     * Filter by comms manager name
     * 
     */
    @Import(name="commsManagerName")
    private @Nullable String commsManagerName;

    /**
     * @return Filter by comms manager name
     * 
     */
    public Optional<String> commsManagerName() {
        return Optional.ofNullable(this.commsManagerName);
    }

    /**
     * The OCID of the root compartment/tenancy.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the root compartment/tenancy.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetServicesFilter> filters;

    public Optional<List<GetServicesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only services underlying a specific platform.
     * 
     */
    @Import(name="platformType")
    private @Nullable String platformType;

    /**
     * @return A filter to return only services underlying a specific platform.
     * 
     */
    public Optional<String> platformType() {
        return Optional.ofNullable(this.platformType);
    }

    private GetServicesPlainArgs() {}

    private GetServicesPlainArgs(GetServicesPlainArgs $) {
        this.commsManagerName = $.commsManagerName;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.platformType = $.platformType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetServicesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetServicesPlainArgs $;

        public Builder() {
            $ = new GetServicesPlainArgs();
        }

        public Builder(GetServicesPlainArgs defaults) {
            $ = new GetServicesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param commsManagerName Filter by comms manager name
         * 
         * @return builder
         * 
         */
        public Builder commsManagerName(@Nullable String commsManagerName) {
            $.commsManagerName = commsManagerName;
            return this;
        }

        /**
         * @param compartmentId The OCID of the root compartment/tenancy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetServicesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetServicesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param platformType A filter to return only services underlying a specific platform.
         * 
         * @return builder
         * 
         */
        public Builder platformType(@Nullable String platformType) {
            $.platformType = platformType;
            return this;
        }

        public GetServicesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetServicesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}

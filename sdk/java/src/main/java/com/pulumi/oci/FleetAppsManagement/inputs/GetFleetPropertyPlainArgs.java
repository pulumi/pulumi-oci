// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFleetPropertyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetPropertyPlainArgs Empty = new GetFleetPropertyPlainArgs();

    /**
     * Unique Fleet identifier.
     * 
     */
    @Import(name="fleetId", required=true)
    private String fleetId;

    /**
     * @return Unique Fleet identifier.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }

    /**
     * Unique fleetProperty identifier.
     * 
     */
    @Import(name="fleetPropertyId", required=true)
    private String fleetPropertyId;

    /**
     * @return Unique fleetProperty identifier.
     * 
     */
    public String fleetPropertyId() {
        return this.fleetPropertyId;
    }

    private GetFleetPropertyPlainArgs() {}

    private GetFleetPropertyPlainArgs(GetFleetPropertyPlainArgs $) {
        this.fleetId = $.fleetId;
        this.fleetPropertyId = $.fleetPropertyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetPropertyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetPropertyPlainArgs $;

        public Builder() {
            $ = new GetFleetPropertyPlainArgs();
        }

        public Builder(GetFleetPropertyPlainArgs defaults) {
            $ = new GetFleetPropertyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fleetId Unique Fleet identifier.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param fleetPropertyId Unique fleetProperty identifier.
         * 
         * @return builder
         * 
         */
        public Builder fleetPropertyId(String fleetPropertyId) {
            $.fleetPropertyId = fleetPropertyId;
            return this;
        }

        public GetFleetPropertyPlainArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetPropertyPlainArgs", "fleetId");
            }
            if ($.fleetPropertyId == null) {
                throw new MissingRequiredPropertyException("GetFleetPropertyPlainArgs", "fleetPropertyId");
            }
            return $;
        }
    }

}

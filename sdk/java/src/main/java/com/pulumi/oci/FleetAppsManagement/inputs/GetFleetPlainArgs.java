// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFleetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetPlainArgs Empty = new GetFleetPlainArgs();

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

    private GetFleetPlainArgs() {}

    private GetFleetPlainArgs(GetFleetPlainArgs $) {
        this.fleetId = $.fleetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetPlainArgs $;

        public Builder() {
            $ = new GetFleetPlainArgs();
        }

        public Builder(GetFleetPlainArgs defaults) {
            $ = new GetFleetPlainArgs(Objects.requireNonNull(defaults));
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

        public GetFleetPlainArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetPlainArgs", "fleetId");
            }
            return $;
        }
    }

}

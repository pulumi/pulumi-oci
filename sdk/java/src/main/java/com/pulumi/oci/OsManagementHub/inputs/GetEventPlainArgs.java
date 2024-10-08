// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetEventPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEventPlainArgs Empty = new GetEventPlainArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the event.
     * 
     */
    @Import(name="eventId", required=true)
    private String eventId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the event.
     * 
     */
    public String eventId() {
        return this.eventId;
    }

    private GetEventPlainArgs() {}

    private GetEventPlainArgs(GetEventPlainArgs $) {
        this.eventId = $.eventId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEventPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEventPlainArgs $;

        public Builder() {
            $ = new GetEventPlainArgs();
        }

        public Builder(GetEventPlainArgs defaults) {
            $ = new GetEventPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param eventId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the event.
         * 
         * @return builder
         * 
         */
        public Builder eventId(String eventId) {
            $.eventId = eventId;
            return this;
        }

        public GetEventPlainArgs build() {
            if ($.eventId == null) {
                throw new MissingRequiredPropertyException("GetEventPlainArgs", "eventId");
            }
            return $;
        }
    }

}

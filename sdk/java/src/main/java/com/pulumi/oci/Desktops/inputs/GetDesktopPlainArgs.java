// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Desktops.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDesktopPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDesktopPlainArgs Empty = new GetDesktopPlainArgs();

    /**
     * The OCID of the desktop.
     * 
     */
    @Import(name="desktopId", required=true)
    private String desktopId;

    /**
     * @return The OCID of the desktop.
     * 
     */
    public String desktopId() {
        return this.desktopId;
    }

    private GetDesktopPlainArgs() {}

    private GetDesktopPlainArgs(GetDesktopPlainArgs $) {
        this.desktopId = $.desktopId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDesktopPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDesktopPlainArgs $;

        public Builder() {
            $ = new GetDesktopPlainArgs();
        }

        public Builder(GetDesktopPlainArgs defaults) {
            $ = new GetDesktopPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param desktopId The OCID of the desktop.
         * 
         * @return builder
         * 
         */
        public Builder desktopId(String desktopId) {
            $.desktopId = desktopId;
            return this;
        }

        public GetDesktopPlainArgs build() {
            if ($.desktopId == null) {
                throw new MissingRequiredPropertyException("GetDesktopPlainArgs", "desktopId");
            }
            return $;
        }
    }

}

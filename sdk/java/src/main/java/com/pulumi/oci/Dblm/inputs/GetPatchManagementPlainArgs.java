// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dblm.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPatchManagementPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPatchManagementPlainArgs Empty = new GetPatchManagementPlainArgs();

    /**
     * The required ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The required ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only database that match the given release version.
     * 
     */
    @Import(name="databaseRelease")
    private @Nullable String databaseRelease;

    /**
     * @return A filter to return only database that match the given release version.
     * 
     */
    public Optional<String> databaseRelease() {
        return Optional.ofNullable(this.databaseRelease);
    }

    /**
     * A filter to return only resources whose timeStarted is greater than or equal to the given date-time.
     * 
     */
    @Import(name="timeStartedGreaterThanOrEqualTo")
    private @Nullable String timeStartedGreaterThanOrEqualTo;

    /**
     * @return A filter to return only resources whose timeStarted is greater than or equal to the given date-time.
     * 
     */
    public Optional<String> timeStartedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeStartedGreaterThanOrEqualTo);
    }

    /**
     * A filter to return only resources whose timeStarted is less than the given date-time.
     * 
     */
    @Import(name="timeStartedLessThan")
    private @Nullable String timeStartedLessThan;

    /**
     * @return A filter to return only resources whose timeStarted is less than the given date-time.
     * 
     */
    public Optional<String> timeStartedLessThan() {
        return Optional.ofNullable(this.timeStartedLessThan);
    }

    private GetPatchManagementPlainArgs() {}

    private GetPatchManagementPlainArgs(GetPatchManagementPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.databaseRelease = $.databaseRelease;
        this.timeStartedGreaterThanOrEqualTo = $.timeStartedGreaterThanOrEqualTo;
        this.timeStartedLessThan = $.timeStartedLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPatchManagementPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPatchManagementPlainArgs $;

        public Builder() {
            $ = new GetPatchManagementPlainArgs();
        }

        public Builder(GetPatchManagementPlainArgs defaults) {
            $ = new GetPatchManagementPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The required ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param databaseRelease A filter to return only database that match the given release version.
         * 
         * @return builder
         * 
         */
        public Builder databaseRelease(@Nullable String databaseRelease) {
            $.databaseRelease = databaseRelease;
            return this;
        }

        /**
         * @param timeStartedGreaterThanOrEqualTo A filter to return only resources whose timeStarted is greater than or equal to the given date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedGreaterThanOrEqualTo(@Nullable String timeStartedGreaterThanOrEqualTo) {
            $.timeStartedGreaterThanOrEqualTo = timeStartedGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeStartedLessThan A filter to return only resources whose timeStarted is less than the given date-time.
         * 
         * @return builder
         * 
         */
        public Builder timeStartedLessThan(@Nullable String timeStartedLessThan) {
            $.timeStartedLessThan = timeStartedLessThan;
            return this;
        }

        public GetPatchManagementPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetPatchManagementPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}

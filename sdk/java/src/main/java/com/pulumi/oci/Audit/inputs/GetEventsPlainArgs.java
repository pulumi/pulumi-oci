// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Audit.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Audit.inputs.GetEventsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEventsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEventsPlainArgs Empty = new GetEventsPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Returns events that were processed before this end date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     * For example, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-01-02T00:00:00Z` will retrieve a list of all events processed on January 1, 2017. Similarly, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-02-01T00:00:00Z` will result in a list of all events processed between January 1, 2017 and January 31, 2017. You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
     * 
     */
    @Import(name="endTime", required=true)
    private String endTime;

    /**
     * @return Returns events that were processed before this end date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     * For example, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-01-02T00:00:00Z` will retrieve a list of all events processed on January 1, 2017. Similarly, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-02-01T00:00:00Z` will result in a list of all events processed between January 1, 2017 and January 31, 2017. You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
     * 
     */
    public String endTime() {
        return this.endTime;
    }

    @Import(name="filters")
    private @Nullable List<GetEventsFilter> filters;

    public Optional<List<GetEventsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Returns events that were processed at or after this start date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     * For example, a start value of `2017-01-15T11:30:00Z` will retrieve a list of all events processed since 30 minutes after the 11th hour of January 15, 2017, in Coordinated Universal Time (UTC). You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
     * 
     */
    @Import(name="startTime", required=true)
    private String startTime;

    /**
     * @return Returns events that were processed at or after this start date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     * 
     * For example, a start value of `2017-01-15T11:30:00Z` will retrieve a list of all events processed since 30 minutes after the 11th hour of January 15, 2017, in Coordinated Universal Time (UTC). You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
     * 
     */
    public String startTime() {
        return this.startTime;
    }

    private GetEventsPlainArgs() {}

    private GetEventsPlainArgs(GetEventsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.endTime = $.endTime;
        this.filters = $.filters;
        this.startTime = $.startTime;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEventsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEventsPlainArgs $;

        public Builder() {
            $ = new GetEventsPlainArgs();
        }

        public Builder(GetEventsPlainArgs defaults) {
            $ = new GetEventsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param endTime Returns events that were processed before this end date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
         * 
         * For example, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-01-02T00:00:00Z` will retrieve a list of all events processed on January 1, 2017. Similarly, a start value of `2017-01-01T00:00:00Z` and an end value of `2017-02-01T00:00:00Z` will result in a list of all events processed between January 1, 2017 and January 31, 2017. You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
         * 
         * @return builder
         * 
         */
        public Builder endTime(String endTime) {
            $.endTime = endTime;
            return this;
        }

        public Builder filters(@Nullable List<GetEventsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetEventsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param startTime Returns events that were processed at or after this start date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
         * 
         * For example, a start value of `2017-01-15T11:30:00Z` will retrieve a list of all events processed since 30 minutes after the 11th hour of January 15, 2017, in Coordinated Universal Time (UTC). You can specify a value with granularity to the minute. Seconds (and milliseconds, if included) must be set to `0`.
         * 
         * @return builder
         * 
         */
        public Builder startTime(String startTime) {
            $.startTime = startTime;
            return this;
        }

        public GetEventsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetEventsPlainArgs", "compartmentId");
            }
            if ($.endTime == null) {
                throw new MissingRequiredPropertyException("GetEventsPlainArgs", "endTime");
            }
            if ($.startTime == null) {
                throw new MissingRequiredPropertyException("GetEventsPlainArgs", "startTime");
            }
            return $;
        }
    }

}

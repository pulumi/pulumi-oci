// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AlarmSuppressionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AlarmSuppressionArgs Empty = new AlarmSuppressionArgs();

    /**
     * (Updatable) Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    @Import(name="timeSuppressFrom", required=true)
    private Output<String> timeSuppressFrom;

    /**
     * @return (Updatable) The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    public Output<String> timeSuppressFrom() {
        return this.timeSuppressFrom;
    }

    /**
     * (Updatable) The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T02:02:29.600Z`
     * 
     */
    @Import(name="timeSuppressUntil", required=true)
    private Output<String> timeSuppressUntil;

    /**
     * @return (Updatable) The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T02:02:29.600Z`
     * 
     */
    public Output<String> timeSuppressUntil() {
        return this.timeSuppressUntil;
    }

    private AlarmSuppressionArgs() {}

    private AlarmSuppressionArgs(AlarmSuppressionArgs $) {
        this.description = $.description;
        this.timeSuppressFrom = $.timeSuppressFrom;
        this.timeSuppressUntil = $.timeSuppressUntil;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AlarmSuppressionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AlarmSuppressionArgs $;

        public Builder() {
            $ = new AlarmSuppressionArgs();
        }

        public Builder(AlarmSuppressionArgs defaults) {
            $ = new AlarmSuppressionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param timeSuppressFrom (Updatable) The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressFrom(Output<String> timeSuppressFrom) {
            $.timeSuppressFrom = timeSuppressFrom;
            return this;
        }

        /**
         * @param timeSuppressFrom (Updatable) The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressFrom(String timeSuppressFrom) {
            return timeSuppressFrom(Output.of(timeSuppressFrom));
        }

        /**
         * @param timeSuppressUntil (Updatable) The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T02:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressUntil(Output<String> timeSuppressUntil) {
            $.timeSuppressUntil = timeSuppressUntil;
            return this;
        }

        /**
         * @param timeSuppressUntil (Updatable) The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T02:02:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeSuppressUntil(String timeSuppressUntil) {
            return timeSuppressUntil(Output.of(timeSuppressUntil));
        }

        public AlarmSuppressionArgs build() {
            $.timeSuppressFrom = Objects.requireNonNull($.timeSuppressFrom, "expected parameter 'timeSuppressFrom' to be non-null");
            $.timeSuppressUntil = Objects.requireNonNull($.timeSuppressUntil, "expected parameter 'timeSuppressUntil' to be non-null");
            return $;
        }
    }

}
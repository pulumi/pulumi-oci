// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DemandSignal.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOccDemandSignalsFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetOccDemandSignalsFilter Empty = new GetOccDemandSignalsFilter();

    @Import(name="name", required=true)
    private String name;

    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    /**
     * The values of forecast.
     * 
     */
    @Import(name="values", required=true)
    private List<String> values;

    /**
     * @return The values of forecast.
     * 
     */
    public List<String> values() {
        return this.values;
    }

    private GetOccDemandSignalsFilter() {}

    private GetOccDemandSignalsFilter(GetOccDemandSignalsFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOccDemandSignalsFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOccDemandSignalsFilter $;

        public Builder() {
            $ = new GetOccDemandSignalsFilter();
        }

        public Builder(GetOccDemandSignalsFilter defaults) {
            $ = new GetOccDemandSignalsFilter(Objects.requireNonNull(defaults));
        }

        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        /**
         * @param values The values of forecast.
         * 
         * @return builder
         * 
         */
        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        /**
         * @param values The values of forecast.
         * 
         * @return builder
         * 
         */
        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetOccDemandSignalsFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetOccDemandSignalsFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetOccDemandSignalsFilter", "values");
            }
            return $;
        }
    }

}

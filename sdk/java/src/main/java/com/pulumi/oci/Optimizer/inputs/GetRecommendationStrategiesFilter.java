// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRecommendationStrategiesFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetRecommendationStrategiesFilter Empty = new GetRecommendationStrategiesFilter();

    /**
     * Optional. A filter that returns results that match the name specified.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    @Import(name="values", required=true)
    private List<String> values;

    public List<String> values() {
        return this.values;
    }

    private GetRecommendationStrategiesFilter() {}

    private GetRecommendationStrategiesFilter(GetRecommendationStrategiesFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRecommendationStrategiesFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecommendationStrategiesFilter $;

        public Builder() {
            $ = new GetRecommendationStrategiesFilter();
        }

        public Builder(GetRecommendationStrategiesFilter defaults) {
            $ = new GetRecommendationStrategiesFilter(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetRecommendationStrategiesFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetRecommendationStrategiesFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetRecommendationStrategiesFilter", "values");
            }
            return $;
        }
    }

}

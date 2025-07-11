import React from 'react';
import { Card, Grid, Text, Title, Accordion, AccordionHeader, AccordionBody } from '@tremor/react';
import { AreaChart, BarChart } from '@tremor/react';
import { SpendMetrics, DailyData, ModelActivityData, MetricWithMetadata, KeyMetricWithMetadata } from './usage/types';
import { Collapse } from 'antd';
import { formatNumberWithCommas } from '@/utils/dataUtils';

interface ActivityMetricsProps {
  modelMetrics: Record<string, ModelActivityData>;
}

const ModelSection = ({ modelName, metrics }: { modelName: string; metrics: ModelActivityData }) => {
  return (
    <div className="space-y-2">
      {/* Summary Cards */}
      <Grid numItems={4} className="gap-4">
        <Card>
          <Text>Total Requests</Text>
          <Title>{metrics.total_requests.toLocaleString()}</Title>
        </Card>
        <Card>
          <Text>Total Successful Requests</Text>
          <Title>{metrics.total_successful_requests.toLocaleString()}</Title>
        </Card>
        <Card>
          <Text>Total Tokens</Text>
          <Title>{metrics.total_tokens.toLocaleString()}</Title>
          <Text>{Math.round(metrics.total_tokens / metrics.total_successful_requests)} avg per successful request</Text>
        </Card>
        <Card>
          <Text>Total Spend</Text>
          <Title>${formatNumberWithCommas(metrics.total_spend, 2)}</Title>
          <Text>${formatNumberWithCommas((metrics.total_spend / metrics.total_successful_requests), 3)} per successful request</Text>
        </Card>
      </Grid>

      {/* Charts */}
      <Grid numItems={2} className="gap-4">
        <Card>
          <Title>Total Tokens</Title>
          <AreaChart    
            data={metrics.daily_data}
            index="date"
            categories={["metrics.prompt_tokens", "metrics.completion_tokens", "metrics.total_tokens"]}
            colors={["blue", "cyan", "indigo"]}
            valueFormatter={(number: number) => number.toLocaleString()}
          />
        </Card>

        <Card>
          <Title>Requests per day</Title>
          <BarChart
            data={metrics.daily_data}
            index="date"
            categories={["metrics.api_requests"]}
            colors={["blue"]}
            valueFormatter={(number: number) => number.toLocaleString()}
          />
        </Card>

        <Card>
          <Title>Spend per day</Title>
          <BarChart
            data={metrics.daily_data}
            index="date"
            categories={["metrics.spend"]}
            colors={["green"]}
            valueFormatter={(value: number) => `$${formatNumberWithCommas(value, 2)}`}
          />
        </Card>

        <Card>
          <Title>Success vs Failed Requests</Title>
          <AreaChart
            data={metrics.daily_data}
            index="date"
            categories={["metrics.successful_requests", "metrics.failed_requests"]}
            colors={["emerald", "red"]}
            valueFormatter={(number: number) => number.toLocaleString()}
            stack
          />
        </Card>
        
        <Card>
          <Title>Prompt Caching Metrics</Title>
          <div className="mb-2">
            <Text>Cache Read: {metrics.total_cache_read_input_tokens?.toLocaleString() || 0} tokens</Text>
            <Text>Cache Creation: {metrics.total_cache_creation_input_tokens?.toLocaleString() || 0} tokens</Text>
          </div>
          <AreaChart
            data={metrics.daily_data}
            index="date"
            categories={["metrics.cache_read_input_tokens", "metrics.cache_creation_input_tokens"]}
            colors={["cyan", "purple"]}
            valueFormatter={(number: number) => number.toLocaleString()}
          />
        </Card>
      </Grid>
    </div>
  );
};

export const ActivityMetrics: React.FC<ActivityMetricsProps> = ({ modelMetrics }) => {
  const modelNames = Object.keys(modelMetrics).sort((a, b) => {
    if (a === '') return 1;
    if (b === '') return -1;
    return modelMetrics[b].total_spend - modelMetrics[a].total_spend;
  });

  // Calculate total metrics across all models
  const totalMetrics = {
    total_requests: 0,
    total_successful_requests: 0,
    total_tokens: 0,
    total_spend: 0,
    total_cache_read_input_tokens: 0,
    total_cache_creation_input_tokens: 0,
    daily_data: {} as Record<string, {
      prompt_tokens: number;
      completion_tokens: number;
      total_tokens: number;
      api_requests: number;
      spend: number;
      successful_requests: number;
      failed_requests: number;
      cache_read_input_tokens: number;
      cache_creation_input_tokens: number;
    }>
  };

  // Aggregate data
  Object.values(modelMetrics).forEach(model => {
    totalMetrics.total_requests += model.total_requests;
    totalMetrics.total_successful_requests += model.total_successful_requests;
    totalMetrics.total_tokens += model.total_tokens;
    totalMetrics.total_spend += model.total_spend;
    totalMetrics.total_cache_read_input_tokens += model.total_cache_read_input_tokens || 0;
    totalMetrics.total_cache_creation_input_tokens += model.total_cache_creation_input_tokens || 0;

    // Aggregate daily data
    model.daily_data.forEach(day => {
      if (!totalMetrics.daily_data[day.date]) {
        totalMetrics.daily_data[day.date] = {
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
          api_requests: 0,
          spend: 0,
          successful_requests: 0,
          failed_requests: 0,
          cache_read_input_tokens: 0,
          cache_creation_input_tokens: 0
        };
      }
      totalMetrics.daily_data[day.date].prompt_tokens += day.metrics.prompt_tokens;
      totalMetrics.daily_data[day.date].completion_tokens += day.metrics.completion_tokens;
      totalMetrics.daily_data[day.date].total_tokens += day.metrics.total_tokens;
      totalMetrics.daily_data[day.date].api_requests += day.metrics.api_requests;
      totalMetrics.daily_data[day.date].spend += day.metrics.spend;
      totalMetrics.daily_data[day.date].successful_requests += day.metrics.successful_requests;
      totalMetrics.daily_data[day.date].failed_requests += day.metrics.failed_requests;
      totalMetrics.daily_data[day.date].cache_read_input_tokens += day.metrics.cache_read_input_tokens || 0;
      totalMetrics.daily_data[day.date].cache_creation_input_tokens += day.metrics.cache_creation_input_tokens || 0;
    });
  });

  // Convert daily_data object to array and sort by date
  const sortedDailyData = Object.entries(totalMetrics.daily_data)
    .map(([date, metrics]) => ({ date, metrics }))
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  return (
    <div className="space-y-8">
      {/* Global Summary */}
      <div className="border rounded-lg p-4">
        <Title>Overall Usage</Title>
        <Grid numItems={4} className="gap-4 mb-4">
          <Card>
            <Text>Total Requests</Text>
            <Title>{totalMetrics.total_requests.toLocaleString()}</Title>
          </Card>
          <Card>
            <Text>Total Successful Requests</Text>
            <Title>{totalMetrics.total_successful_requests.toLocaleString()}</Title>
          </Card>
          <Card>
            <Text>Total Tokens</Text>
            <Title>{totalMetrics.total_tokens.toLocaleString()}</Title>
          </Card>
          <Card>
            <Text>Total Spend</Text>
            <Title>${formatNumberWithCommas(totalMetrics.total_spend, 2)}</Title>
          </Card>
        </Grid>

        <Grid numItems={2} className="gap-4">
          <Card>
            <Title>Total Tokens Over Time</Title>
            <AreaChart    
              data={sortedDailyData}
              index="date"
              categories={["metrics.prompt_tokens", "metrics.completion_tokens", "metrics.total_tokens"]}
              colors={["blue", "cyan", "indigo"]}
              valueFormatter={(number: number) => number.toLocaleString()}
            />
          </Card>
          <Card>
            <Title>Total Requests Over Time</Title>
            <AreaChart
              data={sortedDailyData}
              index="date"
              categories={["metrics.successful_requests", "metrics.failed_requests"]}
              colors={["emerald", "red"]}
              valueFormatter={(number: number) => number.toLocaleString()}
              stack
            />
          </Card>
        </Grid>
      </div>

      {/* Individual Model Sections */}
      <Collapse defaultActiveKey={modelNames[0]}>
        {modelNames.map((modelName) => (
          <Collapse.Panel 
            key={modelName} 
            header={
              <div className="flex justify-between items-center w-full">
                <Title>{modelMetrics[modelName].label || 'Unknown Item'}</Title>
                <div className="flex space-x-4 text-sm text-gray-500">
                  <span>${formatNumberWithCommas(modelMetrics[modelName].total_spend, 2)}</span>
                  <span>{modelMetrics[modelName].total_requests.toLocaleString()} requests</span>
                </div>
              </div>
            }
          >
            <ModelSection 
              modelName={modelName || 'Unknown Model'} 
              metrics={modelMetrics[modelName]} 
            />
          </Collapse.Panel>
        ))}
      </Collapse>
    </div>
  );
};

// Helper function to format key label
const formatKeyLabel = (modelData: KeyMetricWithMetadata, model: string): string => {
  const keyAlias = modelData.metadata.key_alias || `key-hash-${model}`;
  const teamId = modelData.metadata.team_id;
  return teamId ? `${keyAlias} (team_id: ${teamId})` : keyAlias;
};

// Process data function
export const processActivityData = (dailyActivity: { results: DailyData[] }, key: "models" | "api_keys"): Record<string, ModelActivityData> => {
  const modelMetrics: Record<string, ModelActivityData> = {};

  dailyActivity.results.forEach((day) => {
    Object.entries(day.breakdown[key] || {}).forEach(([model, modelData]) => {
      if (!modelMetrics[model]) {
        modelMetrics[model] = {
          label: key === 'api_keys' 
            ? formatKeyLabel(modelData as KeyMetricWithMetadata, model)
            : model,
          total_requests: 0,
          total_successful_requests: 0,
          total_failed_requests: 0,
          total_tokens: 0,
          prompt_tokens: 0,
          completion_tokens: 0,
          total_spend: 0,
          total_cache_read_input_tokens: 0,
          total_cache_creation_input_tokens: 0,
          daily_data: []
        };
      }

      // Update totals
      modelMetrics[model].total_requests += modelData.metrics.api_requests;
      modelMetrics[model].prompt_tokens += modelData.metrics.prompt_tokens;
      modelMetrics[model].completion_tokens += modelData.metrics.completion_tokens;
      modelMetrics[model].total_tokens += modelData.metrics.total_tokens;
      modelMetrics[model].total_spend += modelData.metrics.spend;
      modelMetrics[model].total_successful_requests += modelData.metrics.successful_requests;
      modelMetrics[model].total_failed_requests += modelData.metrics.failed_requests;
      modelMetrics[model].total_cache_read_input_tokens += modelData.metrics.cache_read_input_tokens || 0;
      modelMetrics[model].total_cache_creation_input_tokens += modelData.metrics.cache_creation_input_tokens || 0;

      // Add daily data
      modelMetrics[model].daily_data.push({
        date: day.date,
        metrics: {
          prompt_tokens: modelData.metrics.prompt_tokens,
          completion_tokens: modelData.metrics.completion_tokens,
          total_tokens: modelData.metrics.total_tokens,
          api_requests: modelData.metrics.api_requests,
          spend: modelData.metrics.spend,
          successful_requests: modelData.metrics.successful_requests,
          failed_requests: modelData.metrics.failed_requests,
          cache_read_input_tokens: modelData.metrics.cache_read_input_tokens || 0,
          cache_creation_input_tokens: modelData.metrics.cache_creation_input_tokens || 0
        }
      });
    });
  });

  // Sort daily data
  Object.values(modelMetrics).forEach(metrics => {
    metrics.daily_data.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  });

  return modelMetrics;
}; 
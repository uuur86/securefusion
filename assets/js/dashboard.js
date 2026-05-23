/**
 * SecureFusion Dashboard Script
 *
 * Visualizes Daily and Monthly intrusion attempts.
 *
 * @package securefusion
 */

document.addEventListener('DOMContentLoaded', function() {
    if (typeof securefusionChartData === 'undefined') {
        return;
    }

    var dailyCtx = document.getElementById('fynd-sf-daily-chart');
    var monthlyCtx = document.getElementById('fynd-sf-monthly-chart');

    if (!dailyCtx || !monthlyCtx) {
        return;
    }

    var typeColors = {
        failed_login: {
            border: '#ef4444',
            bg: 'rgba(239, 68, 68, 0.08)',
            solidBg: '#ef4444'
        },
        bad_request: {
            border: '#f97316',
            bg: 'rgba(249, 115, 22, 0.08)',
            solidBg: '#f97316'
        },
        bad_cookie: {
            border: '#eab308',
            bg: 'rgba(234, 179, 8, 0.08)',
            solidBg: '#eab308'
        },
        bad_bot: {
            border: '#a855f7',
            bg: 'rgba(168, 85, 247, 0.08)',
            solidBg: '#a855f7'
        },
        bad_query: {
            border: '#ec4899',
            bg: 'rgba(236, 72, 153, 0.08)',
            solidBg: '#ec4899'
        },
        blocked: {
            border: '#06b6d4',
            bg: 'rgba(6, 182, 212, 0.08)',
            solidBg: '#06b6d4'
        }
    };

    var types = [
        'failed_login',
        'bad_request',
        'bad_cookie',
        'bad_bot',
        'bad_query',
        'blocked'
    ];

    // 1. Daily Line Chart
    var dailyDatasets = [];
    types.forEach(function(type) {
        if (securefusionChartData.daily.datasets[type]) {
            dailyDatasets.push({
                label: securefusionChartData.type_labels[type] || type,
                data: securefusionChartData.daily.datasets[type],
                borderColor: typeColors[type].border,
                backgroundColor: typeColors[type].bg,
                borderWidth: 2,
                tension: 0.35,
                fill: true,
                pointRadius: 2,
                pointHoverRadius: 5
            });
        }
    });

    new Chart(dailyCtx, {
        type: 'line',
        data: {
            labels: securefusionChartData.daily.labels,
            datasets: dailyDatasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 12,
                        padding: 15,
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    padding: 10,
                    bodyFont: {
                        family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                        size: 12
                    },
                    titleFont: {
                        family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                        size: 12,
                        weight: 'bold'
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 10,
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                }
            }
        }
    });

    // 2. Monthly Stacked Bar Chart
    var monthlyDatasets = [];
    types.forEach(function(type) {
        if (securefusionChartData.monthly.datasets[type]) {
            monthlyDatasets.push({
                label: securefusionChartData.type_labels[type] || type,
                data: securefusionChartData.monthly.datasets[type],
                backgroundColor: typeColors[type].solidBg,
                borderRadius: 4
            });
        }
    });

    new Chart(monthlyCtx, {
        type: 'bar',
        data: {
            labels: securefusionChartData.monthly.labels,
            datasets: monthlyDatasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 12,
                        padding: 15,
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    padding: 10,
                    bodyFont: {
                        family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                        size: 12
                    },
                    titleFont: {
                        family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                        size: 12,
                        weight: 'bold'
                    }
                }
            },
            scales: {
                x: {
                    stacked: true,
                    grid: {
                        display: false
                    },
                    ticks: {
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: {
                        precision: 0,
                        font: {
                            family: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
                            size: 11
                        }
                    }
                }
            }
        }
    });
});
